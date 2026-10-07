//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/deployment"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/version"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var (
	installNamespace string
	installRelease   string
	installValues    []string
	installWait      bool
	installCRDs      bool

	installCertFSGroup          int64
	installGetCertRenewInterval time.Duration
	installGetCertRunAsUser     int64
	installGetCertRunAsGroup    int64
	installGetCertRunAsNonRoot  bool
	installCvmMode              string
	installHardwarePlatform     string
	installSingleNode           bool
	installVolumes              bool
	installImagePullSecret      string
	installImageTag             string
	installOperatorKeys         string
	installForce                bool

	installUpstream     string
	installWorkloadRefs []string

	installResolveDigests     bool
	installAttestEnabled      bool
	installMeasurements       []string
	installMeasurementsConfig string
	installRegisters          []string
	installInventoryCIDRs     []string
)

// Flag names referenced in more than one place (registration plus a Changed()
// gate or an arg-builder call). Naming them once keeps the references from
// drifting.
const (
	flagCvmMode          = "cvm-mode"
	flagHardwarePlatform = "hardware-platform"
	flagWorkloadRef      = "workload-ref"
	flagUpstream         = "upstream"
)

// allowedCvmModes is the --cvm-mode enum: bare-metal/gke/aks are node-as-CVM
// deployments. There is no default: the shape must be stated explicitly.
var allowedCvmModes = []string{"bare-metal", "gke", "aks"}

// hostedCvmModes are the lanes whose platform pods belong to the cluster
// provider rather than to C8s, so they are absent from the allowlist the
// install derives. cvmMode=bare-metal is not one: its baked floor already carries the
// system digests.
var hostedCvmModes = []string{"gke", "aks"}

// platformExemptNamespace is the namespace those provider pods run in.
const platformExemptNamespace = "kube-system"

// c8sComponent maps a chart image to the helm value keys --resolve-digests
// pins. valuePrefix is the values path whose image the chart renders;
// repository is that path's values.yaml default, against which the tag is
// resolved. resolveDigests pins both the repository and the digest it resolved
// against, so an operator's -f override of a repository cannot leave the chart
// deploying repoA@<digest-of-repoB>.
type c8sComponent struct {
	valuePrefix  string // values path, e.g. "cds.image" (renders {repository}@{digest})
	repository   string // values.yaml default repository resolved against
	enabledPath  string // values path guarding the render, e.g. "attestationApi.enabled" ("" = always rendered)
	pinnedDigest string // chart-declared digest to pin instead of resolving at the install tag ("" = resolve)
}

// chartComponents reads the component set from the chart at chartPath via
// `helm show values` (which dumps values.yaml without rendering templates, so
// no render guard fires). The valuePath list and each component's repository
// both live in that one values tree, so a single decode serves both. This is
// the single source shared with the chart's c8s.components helper; the Go side
// does not duplicate the list.
func chartComponents(ctx context.Context, chartPath string) ([]c8sComponent, error) {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return nil, fmt.Errorf("helm show values %q: %w", chartPath, err)
	}

	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return nil, fmt.Errorf("parse chart values: %w", err)
	}

	list, ok := tree["c8sComponents"].([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("chart declares no c8sComponents")
	}

	comps := make([]c8sComponent, 0, len(list))
	for _, entry := range list {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("c8sComponents entry is not a mapping: %T", entry)
		}
		valuePath, ok := m["valuePath"].(string)
		if !ok {
			return nil, fmt.Errorf("c8sComponents entry missing string valuePath: %v", m)
		}
		repo, err := stringAtPath(tree, valuePath+".repository")
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", valuePath, err)
		}
		// enabledPath is optional; absent/empty means the component always renders.
		enabledPath, _ := m["enabledPath"].(string)
		// pinnedDigest is optional; absent/empty means resolve at the install tag.
		pinnedDigest, _ := m["pinnedDigest"].(string)
		comps = append(comps, c8sComponent{valuePrefix: valuePath, repository: repo, enabledPath: enabledPath, pinnedDigest: pinnedDigest})
	}
	return comps, nil
}

// operatorKeysPreflight enforces that installing without pinned operator keys is
// a deliberate choice. On the default path — no --operator-keys and no -f values
// file that could carry cds.operatorKeys — it requires --force, because the
// resulting CDS has allowlist writes disabled and nobody could add/remove/upload
// allowlist entries via `c8s allowlist`. When keys are supplied, or the operator
// is managing values via -f, it is a no-op.
func operatorKeysPreflight(operatorKeys string, valuesFiles []string, force bool) (warn string, err error) {
	if operatorKeys != "" || len(valuesFiles) > 0 {
		return "", nil
	}
	if !force {
		return "", fmt.Errorf("no operator keys provided: allowlist writes will be DISABLED — nobody can add/remove/upload allowlist entries via `c8s allowlist`. Re-run with --operator-keys <file> to enable writes, or --force to install with writes disabled anyway")
	}
	return "installing with allowlist writes DISABLED (no --operator-keys); `c8s allowlist` add/remove/upload will not work until you set cds.operatorKeys and reinstall", nil
}

// tdxRTMRPinWarning is the "MRTD does not confer code identity" warning for a
// TDX install that pins no RTMRs: measurement pinning then covers the TDVF
// firmware only, and a host can boot it with a substituted kernel and rootfs.
// Satisfied by --rtmrs or by a -f values file that sets a non-empty cds.rtmrs.
func tdxRTMRPinWarning(hardwarePlatform string, rtmrs, valuesFiles []string) (string, error) {
	if hardwarePlatform != "tdx" || len(rtmrs) > 0 {
		return "", nil
	}
	set, err := valuesFilesSetRTMRs(valuesFiles)
	if err != nil || set {
		return "", err
	}
	return "TDX with no --rtmrs: measurement pinning covers the TDVF firmware only (MRTD), NOT the guest kernel or rootfs — a host can boot the pinned firmware with substituted guest software and still attest. Pass --rtmrs 1=<hex>,2=<hex> (values read off a boot you trust, e.g. `c8s verify --kind lb` verbose output) to pin the guest image in-cluster", nil
}

// valuesFilesSetRTMRs reports whether any -f values file pins TDX RTMRs
// (cds.rtmrs).
func valuesFilesSetRTMRs(files []string) (bool, error) {
	for _, f := range files {
		tree, err := decodeValuesFile(f)
		if err != nil {
			return false, err
		}
		if v, ok := valueAtPath(tree, "cds.rtmrs"); ok {
			if list, isList := v.([]any); isList && len(list) > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// preflightCDSNode fails fast (before the helm install) when no node carries
// the CDS node-selector label. The chart pins the singleton CDS pod to that
// label, so without a matching node CDS stays Pending and `helm --wait` would
// block for the full timeout before failing with an opaque message. The label
// requirement is exact (read straight from the chart's cds.node.selector), not
// a heuristic.
//
// It reads the chart's default values, so it only guards the default path; an
// operator who customizes via -f is trusted to manage node labels themselves
// (the caller skips this when -f is supplied).
func preflightCDSNode(ctx context.Context, chartPath string) error {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return fmt.Errorf("parse chart values: %w", err)
	}

	sel, ok := nestedMap(tree, "cds", "node", "selector")
	if !ok || len(sel) != 1 {
		// The chart's own one-pair guard will report a malformed selector; the
		// preflight only owns the "no matching node" case.
		return nil
	}
	var key, val string
	for k, v := range sel {
		key = k
		val, _ = v.(string)
	}

	labeled, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
		"-l", key+"="+val, "-o", "name").Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes -l %s=%s: %w", key, val, err)
	}
	if strings.TrimSpace(string(labeled)) == "" {
		return fmt.Errorf("no node is labelled %s=%s, so the CDS pod cannot schedule (image policy pins it there). Label one: kubectl label node <node> %s=%s", key, val, key, val)
	}
	return nil
}

// preflightNotBakedNode refuses a second installation over the image-owned
// operator and admission resources. A missing namespace is an ordinary empty
// result; connectivity and authorization failures remain visible.
func preflightNotBakedNode(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "namespace", "c8s-system",
		"-o", "json", "--ignore-not-found").Output()
	if err != nil {
		return fmt.Errorf("inspect c8s-system namespace: %w", withStderr(err))
	}
	if strings.TrimSpace(string(out)) == "" {
		return nil
	}
	var ns struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(out, &ns); err != nil {
		return fmt.Errorf("decode c8s-system namespace: %w", err)
	}
	if ns.Metadata.Labels["confidential.ai/baked"] != "true" {
		return nil
	}
	return fmt.Errorf("c8s-system carries confidential.ai/baked=true: this node image owns the core services, operator and admission policies; configure its signed launch.yaml and workloads instead of running c8s install")
}

// preflightRouterHostPort fails fast when router's host port is already bound on
// every node, so the router pod would sit Pending and `--wait` would time out
// with an opaque scheduler error. The classic collision is a bundled ingress
// controller (rke2 <= v1.35 ships rke2-ingress-nginx, v1.36+ rke2-traefik,
// both on host 80/443). Reads chart
// defaults, so the caller gates it to the default (no -f) path where they apply.
func preflightRouterHostPort(ctx context.Context, chartPath, namespace string) error {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return fmt.Errorf("parse chart values: %w", err)
	}
	if !boolAtPath(tree, "router.enabled") || !boolAtPath(tree, "router.hostPort.enabled") {
		return nil
	}
	port, err := routerHostPort(tree)
	if err != nil {
		return err
	}

	nodesOut, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
		"-o", `jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}`).Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes: %w", err)
	}
	var nodes []string
	for n := range strings.SplitSeq(strings.TrimSpace(string(nodesOut)), "\n") {
		if n = strings.TrimSpace(n); n != "" {
			nodes = append(nodes, n)
		}
	}

	podsJSON, err := exec.CommandContext(ctx, "kubectl", "get", "pods",
		"--all-namespaces", "-o", "json").Output()
	if err != nil {
		return fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	var list corev1.PodList
	if err := json.Unmarshal(podsJSON, &list); err != nil {
		return fmt.Errorf("parse pod list: %w", err)
	}

	// Ignore the install namespace: C8s's own router pod lives there, so a
	// re-install (Recreate) does not flag itself.
	if blocked, holders := hostPortConflict(list.Items, nodes, port, namespace); blocked {
		return fmt.Errorf("router wants host port %d but it is already bound on every node by: %s. "+
			"router would stay Pending and --wait would time out. Reach router via its Service, or install with "+
			"-f setting router.hostPort.enabled=false (or router.hostPort.https to a free port, or router.enabled=false)",
			port, strings.Join(holders, ", "))
	}
	return nil
}

// boolAtPath walks a dotted path through a decoded YAML tree and returns the
// bool at it, or false if a segment is missing or the leaf is not a bool.
func boolAtPath(tree map[string]any, path string) bool {
	var cur any = tree
	for seg := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur = m[seg]
	}
	b, _ := cur.(bool)
	return b
}

// routerHostPort resolves router.hostPort.https, defaulting to 443 (the chart's
// empty-string default derives 443).
func routerHostPort(tree map[string]any) (int32, error) {
	m, ok := nestedMap(tree, "router", "hostPort")
	if !ok {
		return 443, nil
	}
	var port int64
	switch v := m["https"].(type) {
	case nil:
		return 443, nil
	case string:
		if v == "" {
			return 443, nil
		}
		// ParseInt with bitSize 32 rejects values that would overflow int32.
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("router.hostPort.https %q is not a valid port number: %w", v, err)
		}
		port = n
	case int:
		port = int64(v)
	case float64:
		port = int64(v)
	default:
		return 0, fmt.Errorf("router.hostPort.https has unexpected type %T", v)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("router.hostPort.https %d is out of range (1-65535)", port)
	}
	return int32(port), nil
}

// hostPortConflict reports whether port is already bound on every node (so a new
// host-port pod cannot schedule anywhere), along with the pods that hold it.
// Pods in ignoreNamespace are skipped so C8s's own router does not self-flag.
func hostPortConflict(pods []corev1.Pod, nodes []string, port int32, ignoreNamespace string) (bool, []string) {
	taken := map[string]bool{}
	holderSet := map[string]bool{}
	for _, p := range pods {
		if p.Namespace == ignoreNamespace || !podBindsHostPort(p, port) {
			continue
		}
		holderSet[p.Namespace+"/"+p.Name] = true
		if p.Spec.NodeName != "" {
			taken[p.Spec.NodeName] = true
		}
	}
	holders := make([]string, 0, len(holderSet))
	for h := range holderSet {
		holders = append(holders, h)
	}
	sort.Strings(holders)

	if len(nodes) == 0 {
		return false, holders
	}
	for _, n := range nodes {
		if !taken[n] {
			return false, holders // a free node exists; router can bind there
		}
	}
	return true, holders
}

func podBindsHostPort(p corev1.Pod, port int32) bool {
	for _, c := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
		for _, cp := range c.Ports {
			if cp.HostPort == port {
				return true
			}
		}
	}
	return false
}

// policyModeFailClosed is the image-policy mode that denies. In `audit` the
// plugin logs the would-be denial and creates the container anyway.
const policyModeFailClosed = "fail-closed"

// deniedImagesListed caps the images the refusal prints; the rest are counted.
const deniedImagesListed = 20

// preflightImagePolicy refuses an install whose rendered image policy would
// deny the cluster's own platform pods. Registering the plugin restarts
// containerd, which recreates those containers under the new policy: on a
// self-managed control plane the static pods are denied and the API server
// never returns, leaving nothing but out-of-band root to recover with.
//
// It reads the EFFECTIVE values (chart defaults + -f + computed), so it runs on
// every install including -f ones — whoever wrote the policy, a cluster whose
// own pods it denies is broken the same way. Cluster access is read-only.
//
// It also reports to w what an exempt namespace will admit (see
// reportExemptedImages).
//
// --force installs anyway, and returns the same list as a warning.
func preflightImagePolicy(ctx context.Context, w io.Writer, values map[string]any, components []c8sComponent, releaseNamespace string, force bool) (warn string, err error) {
	if !boolAtPath(values, "nriImagePolicy.enabled") {
		return "", nil
	}
	// Under .baked the node's floor is the one the image build rendered — the
	// RKE2 system digests included — and the chart cannot see it, so every
	// baked-floor pod here reads as denied. The plugin has also been enforcing
	// since boot, so what runs is already admitted and the pins the installer
	// writes change who may serve the allowlist, not what it admits.
	if boolAtPath(values, "nriImagePolicy.baked") {
		return "", nil
	}
	// A mode the chart cannot read is the render guard's to reject, not this
	// preflight's; either way nothing is denied here.
	if mode, err := stringAtPath(values, "nriImagePolicy.policy.mode"); err != nil || mode != policyModeFailClosed {
		return "", nil
	}

	podsJSON, err := exec.CommandContext(ctx, "kubectl", "get", "pods",
		"--all-namespaces", "-o", "json").Output()
	if err != nil {
		return "", fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	var list corev1.PodList
	if err := json.Unmarshal(podsJSON, &list); err != nil {
		return "", fmt.Errorf("parse pod list: %w", err)
	}

	exempt := stringsAtPath(values, exemptNamespacesPath)
	reportExemptedImages(w, exempt, exemptedPlatformImages(list.Items, exempt))

	denied := deniedPlatformImages(list.Items, releaseNamespace, exempt, admissibleDigests(values, components))
	if len(denied) == 0 {
		return "", nil
	}
	if force {
		return "installing a fail-closed image policy that denies " + deniedSummary(denied) + "; those containers will not come back after the containerd restart", nil
	}
	return "", fmt.Errorf("fail-closed image admission would deny %s the cluster runs, and registering the plugin restarts containerd — the denied containers would not come back:\n  %s\nAdmit their namespaces with -f setting nriImagePolicy.policy.exemptNamespaces, admit their digests with nriImagePolicy.bootstrapAllowlist.workloads entries under any command and args, or re-run with --force to install anyway",
		deniedSummary(denied), strings.Join(denied, "\n  "))
}

// deniedSummary names the size of the denied set for a one-line message.
func deniedSummary(denied []string) string {
	if len(denied) == 1 {
		return "1 platform image"
	}
	return fmt.Sprintf("%d platform images", len(denied))
}

// platformImageLines returns one "namespace/pod  repository@digest" line per
// (namespace, digest) accept keeps, sorted. A DaemonSet runs the same image on
// every node, so entries are deduplicated and named by the first pod carrying
// them. A pod the kubelet has finished with is skipped: it has no container the
// containerd restart will recreate, so the policy never sees its images.
func platformImageLines(pods []corev1.Pod, accept func(namespace, digest string) bool) []string {
	seen := map[string]bool{}
	var lines []string
	for _, p := range pods {
		if !platformPod(p) || isTerminalPod(p) {
			continue
		}
		for _, st := range podContainerStatuses(p) {
			digest := imageDigest(st.ImageID, st.Image)
			if digest == "" || !accept(p.Namespace, digest) {
				continue
			}
			if key := p.Namespace + "\x00" + digest; !seen[key] {
				seen[key] = true
				lines = append(lines, fmt.Sprintf("%s/%s  %s@%s", p.Namespace, p.Name, imageRepository(st.Image, st.ImageID), digest))
			}
		}
	}
	slices.Sort(lines)
	return lines
}

func isTerminalPod(p corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

// deniedPlatformImages lists the platform-pod images the policy would deny.
func deniedPlatformImages(pods []corev1.Pod, releaseNamespace string, exempt []string, admitted map[string]bool) []string {
	denied := platformImageLines(pods, func(namespace, digest string) bool {
		return namespace != releaseNamespace && !slices.Contains(exempt, namespace) && !admitted[digest]
	})
	if len(denied) > deniedImagesListed {
		rest := len(denied) - deniedImagesListed
		denied = append(denied[:deniedImagesListed:deniedImagesListed], fmt.Sprintf("… and %d more", rest))
	}
	return denied
}

// exemptedPlatformImages lists the platform-pod images an exempt namespace
// admits by captured digest.
func exemptedPlatformImages(pods []corev1.Pod, exempt []string) []string {
	return platformImageLines(pods, func(namespace, _ string) bool {
		return slices.Contains(exempt, namespace)
	})
}

// reportExemptedImages prints what the exemption will admit. The plugin freezes
// the digest set per node under its own cache dir, so an install is the one
// place an operator can review it — and the one place where admitting the same
// digests by entry instead is still a choice. Uncapped: a truncated audit list
// is not one.
func reportExemptedImages(w io.Writer, exempt, images []string) {
	if len(images) == 0 {
		return
	}
	fmt.Fprintf(w, "+ image policy: %s admitted by captured digest. The plugin freezes what runs\n"+
		"  there when it first connects; as of now that is %d image(s):\n", strings.Join(exempt, ", "), len(images))
	for _, image := range images {
		fmt.Fprintf(w, "    %s\n", image)
	}
	fmt.Fprintf(w, "  To pin them explicitly instead, admit these digests with\n"+
		"  nriImagePolicy.bootstrapAllowlist.workloads entries under any command and args\n"+
		"  (c8s allowlist add writes the same shape) and set %s: [] via -f.\n", exemptNamespacesPath)
}

// platformPod reports whether a pod belongs to the cluster's own platform
// rather than to a tenant: a static pod (the control plane, which the kubelet
// mirrors into the API) or a DaemonSet pod (CNI, kube-proxy, CSI and device
// plugins). Those are the pods a containerd restart takes down and the cluster
// cannot be repaired without. A tenant Deployment denied by a policy the
// operator is deliberately installing is theirs to allowlist, not a refusal.
func platformPod(p corev1.Pod) bool {
	if _, mirror := p.Annotations[corev1.MirrorPodAnnotationKey]; mirror {
		return true
	}
	return slices.ContainsFunc(p.OwnerReferences, func(o metav1.OwnerReference) bool {
		return o.Kind == "DaemonSet"
	})
}

// podContainerStatuses is every container the kubelet reports for a pod, so
// init and ephemeral containers are checked alongside the main ones.
func podContainerStatuses(p corev1.Pod) []corev1.ContainerStatus {
	return slices.Concat(p.Status.InitContainerStatuses, p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses)
}

// imageDigest reads the sha256 the policy matches on out of the first
// reference that carries one — the runtime's resolved imageID for preference,
// since a tag says nothing about what admission will see. Empty means no
// reference carried a digest (a container that has not pulled yet), which
// nothing here can evaluate.
//
// A container status reports imageID as a digested reference, as a bare
// digest, or — on older runtimes — behind a docker-pullable:// prefix.
func imageDigest(refs ...string) string {
	for _, ref := range refs {
		ref = strings.TrimPrefix(ref, "docker-pullable://")
		if strings.HasPrefix(ref, "sha256:") {
			return ref
		}
		named, err := reference.ParseDockerRef(ref)
		if err != nil {
			continue
		}
		if digested, ok := named.(reference.Digested); ok {
			return digested.Digest().String()
		}
	}
	return ""
}

// imageRepository normalizes the first parseable reference to the bare
// repository the digest is reported against — the same form
// workloadImageAllowlistEntry writes as an entry's image label.
func imageRepository(refs ...string) string {
	for _, ref := range refs {
		named, err := reference.ParseDockerRef(strings.TrimPrefix(ref, "docker-pullable://"))
		if err != nil {
			continue
		}
		return reference.TrimNamed(named).String()
	}
	return ""
}

// admissibleDigests collects the image digests the rendered allowlist admits:
// the per-container digests of the operator-supplied bootstrapAllowlist
// workloads plus every pinned component image the chart derives from. The
// component digests are taken whether or not derivation is on and whether or
// not the component renders — a digest here that the chart would not actually
// emit can only mean one fewer image reported, and no C8s component image runs
// in a platform pod.
func admissibleDigests(values map[string]any, components []c8sComponent) map[string]bool {
	admitted := map[string]bool{}
	for _, c := range components {
		if digest, err := stringAtPath(values, c.valuePrefix+".digest"); err == nil && digest != "" {
			admitted[digest] = true
		}
	}
	if workloads, ok := nestedMap(values, "nriImagePolicy", "bootstrapAllowlist", "workloads"); ok {
		for _, w := range workloads {
			for _, digest := range workloadDigests(w) {
				admitted[digest] = true
			}
		}
	}
	return admitted
}

// workloadDigests pulls the container digests out of one decoded
// bootstrapAllowlist.workloads entry.
func workloadDigests(workload any) []string {
	m, ok := workload.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for _, field := range []string{"initContainers", "containers"} {
		list, _ := m[field].([]any)
		for _, entry := range list {
			c, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if digest, ok := c["digest"].(string); ok && digest != "" {
				out = append(out, digest)
			}
		}
	}
	return out
}

// stringsAtPath returns the string list at a dotted path; a missing key, a
// non-list leaf, or a non-string element yields what could be read.
func stringsAtPath(tree map[string]any, path string) []string {
	value, ok := valueAtPath(tree, path)
	if !ok {
		return nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, entry := range list {
		if s, ok := entry.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// clusterDistroNodes reads every node's kubeletVersion via kubectl and splits
// the nodes into RKE2-built vs upstream-built buckets.
//
// Detection: RKE2's bundled kubelet stamps a "+rke2" build suffix onto
// status.nodeInfo.kubeletVersion (e.g. v1.29.5+rke2r1); vanilla upstream
// kubelet has no suffix. The suffix is the only reliable distro signal
// kubectl can see without going on-host.
func clusterDistroNodes(ctx context.Context) (rke2, other []string, err error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
		"-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\n"}{end}`).Output()
	if err != nil {
		return nil, nil, fmt.Errorf("kubectl get nodes: %w", withStderr(err))
	}
	rke2, other = classifyDistroNodes(strings.Split(strings.TrimSpace(string(out)), "\n"))
	return rke2, other, nil
}

// detectDistro picks the host distro for an install, from the cluster's
// kubelet versions.
func detectDistro(ctx context.Context) (string, error) {
	rke2Nodes, otherNodes, err := clusterDistroNodes(ctx)
	if err != nil {
		return "", err
	}
	return chooseDistro(rke2Nodes, otherNodes)
}

// classifyDistroNodes splits "name\tkubeletVersion" lines into RKE2-built vs
// upstream-built buckets by the "+rke2" build-metadata suffix RKE2's kubelet
// build carries. Lines without a tab (no kubeletVersion reported) are skipped
// — a node Status with no kubeletVersion can't be classified either way, so
// detection ignores it rather than guessing.
func classifyDistroNodes(lines []string) (rke2, other []string) {
	for _, l := range lines {
		name, ver, ok := strings.Cut(l, "\t")
		if !ok || name == "" {
			continue
		}
		if strings.Contains(ver, "+rke2") {
			rke2 = append(rke2, name)
		} else {
			other = append(other, name)
		}
	}
	return
}

// chooseDistro maps the node classification to a distro value: any RKE2 node
// (and no upstream ones) selects rke2; otherwise k8s, which also covers an
// empty or unclassifiable node list — the chart default and the only safe
// guess. A mixed cluster has no single right answer: nri-image-policy patches
// a distro-specific containerd path on every selected node, so it demands an
// explicit choice via -f instead of guessing.
func chooseDistro(rke2Nodes, otherNodes []string) (string, error) {
	if len(rke2Nodes) > 0 && len(otherNodes) > 0 {
		return "", fmt.Errorf("cannot detect the host distro: the cluster mixes RKE2 nodes (%s) and non-RKE2 nodes (%s). Set nriImagePolicy.distro and restrict the install with nriImagePolicy.nodeSelector via -f", strings.Join(rke2Nodes, ", "), strings.Join(otherNodes, ", "))
	}
	if len(rke2Nodes) > 0 {
		return "rke2", nil
	}
	return "k8s", nil
}

// nestedMap walks map keys and returns the map[string]any at the path.
func nestedMap(tree map[string]any, keys ...string) (map[string]any, bool) {
	cur := tree
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// stringAtPath walks a dotted path through a decoded YAML tree and returns the
// string at it, erroring if a segment is missing or the leaf is not a string.
func stringAtPath(tree map[string]any, path string) (string, error) {
	var cur any = tree
	for seg := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("path %q: %q is not a mapping", path, seg)
		}
		cur, ok = m[seg]
		if !ok {
			return "", fmt.Errorf("path %q: missing segment %q", path, seg)
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("path %q: not a string (%T)", path, cur)
	}
	return s, nil
}

// valueAtPath walks a dotted path through a decoded YAML tree. ok reports
// whether the key is there, so a key written with a null or empty value is
// distinguishable from one that is absent.
func valueAtPath(tree map[string]any, path string) (value any, ok bool) {
	var cur any = tree
	for seg := range strings.SplitSeq(path, ".") {
		m, isMap := cur.(map[string]any)
		if !isMap {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// decodeValuesFile reads and parses one -f values file.
func decodeValuesFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read values file %q: %w", path, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("parse values file %q: %w", path, err)
	}
	return tree, nil
}

// valuesFilesSetDistro reports whether any -f values file explicitly sets
// nriImagePolicy.distro. When one does, that file owns the host containerd
// layout and cluster auto-detection must stand aside; when none does,
// detection still applies even though other values were supplied.
func valuesFilesSetDistro(files []string) (bool, error) {
	for _, f := range files {
		tree, err := decodeValuesFile(f)
		if err != nil {
			return false, err
		}
		for _, path := range []string{"nriImagePolicy.distro"} {
			if v, err := stringAtPath(tree, path); err == nil && v != "" {
				return true, nil
			}
		}
	}
	return false, nil
}

// materializeStdinValues replaces each "-" entry (helm's -f - idiom) with a
// temp file holding the piped values, so every values consumer — the distro
// and TEE-selector scans, effectiveValues, and helm itself — reads the same
// bytes. Stdin is drained once, so a repeated "-" gets an empty file, as does
// helm's own repeated -f -. The returned cleanup removes the temp files.
func materializeStdinValues(files []string, stdin io.Reader) ([]string, func(), error) {
	out := make([]string, 0, len(files))
	var temps []string
	cleanup := func() {
		for _, t := range temps {
			os.Remove(t)
		}
	}
	for _, f := range files {
		if f != "-" {
			out = append(out, f)
			continue
		}
		data, err := io.ReadAll(stdin)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("read values from stdin: %w", err)
		}
		tmp, err := os.CreateTemp("", "c8s-install-stdin-*.yaml")
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("create stdin values file: %w", err)
		}
		_, werr := tmp.Write(data)
		cerr := tmp.Close()
		if err := errors.Join(werr, cerr); err != nil {
			os.Remove(tmp.Name())
			cleanup()
			return nil, nil, fmt.Errorf("write stdin values file: %w", err)
		}
		temps = append(temps, tmp.Name())
		out = append(out, tmp.Name())
	}
	return out, cleanup, nil
}

// exemptNamespacesPath is the image-policy value the hosted lanes default.
const exemptNamespacesPath = "nriImagePolicy.policy.exemptNamespaces"

// valuesFilesSetExemptNamespaces reports whether any -f values file writes
// nriImagePolicy.policy.exemptNamespaces. Key presence is the test, an empty
// list included: writing one chooses digest-only admission, and the
// hosted-lane default must leave that choice standing.
func valuesFilesSetExemptNamespaces(files []string) (bool, error) {
	for _, f := range files {
		tree, err := decodeValuesFile(f)
		if err != nil {
			return false, err
		}
		if _, ok := valueAtPath(tree, exemptNamespacesPath); ok {
			return true, nil
		}
	}
	return false, nil
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the c8s operator, CRDs, attestation-api, and component charts via Helm",
	Long: `Extracts the bundled c8s Helm chart and runs
'helm upgrade --install' against the current kubeconfig context. Deploys:

  - the install namespace (labeled pod-security=privileged)
  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the ConfidentialWorkload CRD
  - the mutating admission webhook configuration
  - the attestation-api DaemonSet (per-node /attest + /verify)
  - the CDS trust root (attestation, mesh CA, leaf signing)
  - the pod-validating webhook configuration
  - the nri-image-policy and router components

The host distro (k8s vs rke2) is detected from the cluster's kubelet versions;
override nriImagePolicy.distro via -f for a layout detection
cannot see. On RKE2 the nri-image-policy DaemonSets carry a
containerd-prep initContainer that wires up the drop-in import; no node
preparation is required beyond a running cluster.

On the hosted lanes (--cvm-mode=gke/aks) the provider's kube-system pods are
not on the c8s allowlist, so the install renders
nriImagePolicy.policy.exemptNamespaces=[kube-system], admitting them by the
digests they run at the plugin's first connect. A -f file that sets that key
owns it. Either way the install refuses, before it touches the cluster, when the
resolved policy would deny a platform pod the cluster is already running:
registering the plugin restarts containerd, and a denied control-plane container
does not come back. --force installs anyway.

By default each component image tag is resolved to its registry digest (via the
'crane' CLI) and pinned, including the CDS digest the image-policy floor and
render guard require, and nriImagePolicy.bootstrapAllowlist.deriveComponents is
enabled so the resolved images are added to the NRI allowlist. This makes a
plain install satisfy the floor with no hand-written values. Pass
--resolve-digests=false when you supply the digests yourself via -f; the
render guards then require those values.

When the c8s images live in a registry that requires authentication, create a
kubernetes.io/dockerconfigjson Secret in the release namespace and pass
--image-pull-secret <name>: the chart wires it into every component's
imagePullSecrets, so pods authenticate from first start.
This is the cluster-side (kubelet) credential; digest resolution runs locally
via crane and uses your local docker login.

--volumes deploys volumed, the node agent that opens a pod's encrypted volumes
into its mount namespace (docs/volumes.md).

To adopt already-running workloads, pass --workload-ref <id>=<namespace>/<kind>/<name>[:<port>].
The release namespace is excluded from workload injection, so adopted workloads
must live in a separate namespace. After the chart is ready, install patches each
workload's pod template with confidential.ai/cw=<id>; the rollout then goes
through the c8s webhook and the operator provisions the c8s-<id> headless Service.
To front one of them behind router, give that ref a :<port> and pass --upstream <id>;
router routes its catch-all to that adopted workload's headless Service
(c8s-<id>.<ns>.svc.cluster.local:<port>). With --resolve-digests, install also
resolves adopted workload images into nriImagePolicy.bootstrapAllowlist.workloads
entries admitting them under any command and args, so image admission (the host
NRI plugin) allows those
rollouts.

Requires the 'helm' and 'kubectl' CLIs to be on PATH, and 'crane' unless
--resolve-digests=false.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateCvmMode(installCvmMode); err != nil {
			return err
		}
		if err := validateHardwarePlatform(installHardwarePlatform); err != nil {
			return err
		}
		// Substitute any "-f -" before anything reads installValues, so the
		// preflights and helm all see the piped values at a real path.
		substituted, stdinCleanup, err := materializeStdinValues(installValues, cmd.InOrStdin())
		if err != nil {
			return err
		}
		defer stdinCleanup()
		installValues = substituted
		adoptions, err := collectWorkloadAdoptions(installWorkloadRefs)
		if err != nil {
			return err
		}
		if err := validateWorkloadAdoptionFlags(installNamespace, adoptions, installWait); err != nil {
			return err
		}
		if _, err := upstreamAddress(installUpstream, adoptions); err != nil {
			return err
		}
		if warn, err := operatorKeysPreflight(installOperatorKeys, installValues, installForce); err != nil {
			return err
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, "warning: "+warn)
		}
		if warn, err := tdxRTMRPinWarning(installHardwarePlatform, installRegisters, installValues); err != nil {
			return err
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, "warning: "+warn)
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		if _, err := exec.LookPath("kubectl"); err != nil {
			return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
		}
		if err := preflightNotBakedNode(cmd.Context()); err != nil {
			return err
		}
		// Always read the adopted workloads, even when --resolve-digests=false
		// discards workloadImages: this is the only pre-install existence check,
		// so it fails fast before any helm install or post-install patch runs.
		// Don't gate it on installResolveDigests.
		workloadImages := []string{}
		for _, adoption := range adoptions {
			images, err := adoptedWorkloadImages(cmd.Context(), adoption.ref)
			if err != nil {
				return err
			}
			reportAdoptedImages(adoption, images)
			workloadImages = append(workloadImages, images...)
		}

		dir, err := extractChart()
		if err != nil {
			return fmt.Errorf("extract embedded chart: %w", err)
		}
		defer os.RemoveAll(dir)

		chartPath := filepath.Join(dir, helmchart.ChartRoot)
		components, err := chartComponents(cmd.Context(), chartPath)
		if err != nil {
			return fmt.Errorf("read chart components: %w", err)
		}
		imageTag := resolveImageTag()
		// nri-image-policy must bind the host's containerd
		// layout in every install mode, so the distro is detected from the
		// cluster's kubelet versions and plumbed; letting the chart default
		// (k8s) stand would silently mis-target RKE2. Detection is suppressed
		// only when a -f file actually sets nriImagePolicy.distro
		// (that file then owns the layout) — not merely because some -f is
		// present. buildValueArgs skips the distro when it is empty.
		distro := ""
		distroInValues, err := valuesFilesSetDistro(installValues)
		if err != nil {
			return err
		}
		if !distroInValues {
			distro, err = detectDistro(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "+ detected host distro: %s\n", distro)
		}
		// The sandbox-digests callback dials node addresses and nothing else.
		// Resolve here, where the cluster is reachable, that CDS can bound
		// it — a default install must not quietly ship with sandbox identity
		// disabled. Must run before buildValueArgs, which folds an explicit
		// --node-cidr into the
		// computed values.
		resolved, err := resolveInventoryCIDRs(cmd.Context(), installInventoryCIDRs)
		if err != nil {
			return err
		}
		installInventoryCIDRs = resolved

		// The computed values are shared with `c8s render-values` via
		// buildValueArgs, then written to one values file rather than passed as a
		// pile of --set flags. The contract that the CLI's flag-derived values
		// override an operator's -f is preserved by ordering: the computed file
		// is the LAST -f, so it wins on the keys it sets (matching the previous
		// "--set beats -f" precedence) while the operator's files supply the rest.
		setArgs, err := buildValueArgs(cmd.Context(), cmd, chartPath, components, imageTag, distro, appendResolvedDigestArgs)
		if err != nil {
			return err
		}
		if installResolveDigests {
			setArgs, err = appendResolvedWorkloadImageArgs(cmd.Context(), setArgs, workloadImages)
			if err != nil {
				return err
			}
		}
		computedValues, err := writeComputedValues(setArgs)
		if err != nil {
			return err
		}
		defer os.Remove(computedValues)
		helmArgs := buildInstallHelmArgs(chartPath, computedValues, installValues, installCRDs, installWait)

		// Fail fast on the default path if the CDS node is unlabelled, before
		// mutating the cluster. Skipped when -f is supplied: a custom values
		// file may disable image policy or change the selector, and the operator
		// owns node labels in that case. Also skipped under --single-node, which
		// clears the selector so no node needs the label.
		if len(installValues) == 0 && !installSingleNode {
			if err := preflightCDSNode(cmd.Context(), chartPath); err != nil {
				return err
			}
		}

		// Fail fast when router's host port is already taken cluster-wide (e.g.
		// an existing ingress owns 443), which would otherwise wedge `--wait`.
		// Default path only: a -f owner controls router.* and node placement.
		if len(installValues) == 0 {
			if err := preflightRouterHostPort(cmd.Context(), chartPath, installNamespace); err != nil {
				return err
			}
		}

		// Digest resolution off + default values: verify at least the
		// operator image exists (see preflightOperatorImage); a -f owner may
		// pin different repositories or digests.
		if !installResolveDigests && len(installValues) == 0 {
			if err := preflightOperatorImage(cmd.Context(), components, imageTag); err != nil {
				return err
			}
		}

		if installImagePullSecret != "" {
			if err := preflightImagePullSecret(cmd.Context(), installNamespace, installImagePullSecret); err != nil {
				return err
			}
		}

		// The values the release will actually render with (chart defaults + -f
		// + computed), read once and shared by the checks below.
		values, err := effectiveValues(cmd.Context(), chartPath, setArgs)
		if err != nil {
			return err
		}

		// Fail fast when the policy this install renders would deny the
		// cluster's own platform pods: registering the plugin restarts
		// containerd, and a denied control-plane static pod takes the API
		// server with it. Read-only, so it runs with -f too.
		if warn, err := preflightImagePolicy(cmd.Context(), os.Stdout, values, components, installNamespace, installForce); err != nil {
			return err
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, "warning: "+warn)
		}

		// The install always ships pods that exceed the restricted pod-security
		// profile: nri-image-policy runs privileged unconditionally and
		// attestation-api needs SYS_RAWIO (node/gke) or privileged (aks).
		// No supported shape fits restricted, so
		// the namespace is always labelled privileged (a CIS-hardened cluster, e.g.
		// RKE2 with profile: cis, would otherwise reject those pods at admission).
		if err := applyNamespace(cmd.Context(), installNamespace); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
		hc := exec.CommandContext(cmd.Context(), "helm", helmArgs...)
		hc.Stdout, hc.Stderr = os.Stdout, os.Stderr
		if err := hc.Run(); err != nil {
			return fmt.Errorf("helm install failed: %w", err)
		}
		for _, adoption := range adoptions {
			if err := patchAdoptedWorkload(cmd.Context(), adoption.ref, adoption.cwID); err != nil {
				return err
			}
		}

		printAttestVerifyHint(os.Stdout, installAttestEnabled)
		return nil
	},
}

// printAttestVerifyHint surfaces measurement pinning after an install with the
// router attestation sidecar (on by default).
//
// The cluster's launch measurement M is a property of the deployed node image
// (its manifest.json), known before the cluster runs. --measurements <M> pins it
// into the internal mesh (cds.measurements) on the install itself; external
// clients pin the same M when they verify. When
// --measurements was omitted, the mesh accepts any attested peer (UNSAFE), so
// the hint says how to fix it.
func printAttestVerifyHint(w io.Writer, attestEnabled bool) {
	if !attestEnabled {
		return
	}
	if len(installMeasurements) > 0 {
		fmt.Fprintln(w, "+ router attestation sidecar enabled; mesh pinned to --measurements.")
		fmt.Fprintln(w, "  Clients verify with the same M: c8s verify https://<router> --measurements <M>")
		return
	}
	fmt.Fprintln(w, "+ router attestation sidecar enabled, but the mesh is UNPINNED (accepts any")
	fmt.Fprintln(w, "  attested TEE). Pin it with the node image's launch measurement M (its")
	fmt.Fprintln(w, "  manifest.json): reinstall with --measurements <M>. Clients verify with the")
	fmt.Fprintln(w, "  same M: c8s verify https://<router> --measurements <M>.")
}

// extractChart writes the embedded chart tree to a fresh tmpdir and returns
// its path. Caller must RemoveAll when done.
func extractChart() (string, error) {
	dir, err := os.MkdirTemp("", "c8s-chart-*")
	if err != nil {
		return "", err
	}
	if err := os.CopyFS(dir, helmchart.ChartFS); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// applyNamespace creates the install namespace before helm, labelled to allow
// privileged pods (the install's privileged components, see RunE). helm
// --create-namespace cannot set labels, so we always pre-apply.
func applyNamespace(ctx context.Context, namespace string) error {
	manifest, err := namespaceManifest(namespace)
	if err != nil {
		return fmt.Errorf("render namespace manifest: %w", err)
	}
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # Namespace/%s (pod-security=privileged)\n", namespace)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply namespace %q: %w", namespace, err)
	}
	return nil
}

// namespaceManifest renders the release Namespace as JSON (valid kubectl apply
// input), labelled privileged at the enforce, warn, and audit modes so the
// install's privileged pods admit on a cluster whose default profile is
// stricter (e.g. CIS-hardened restricted).
func namespaceManifest(namespace string) ([]byte, error) {
	ns := corev1.Namespace{
		APIVersion: "v1", Kind: "Namespace",
		Name: namespace,
		Labels: map[string]string{
			"pod-security.kubernetes.io/enforce": "privileged",
			"pod-security.kubernetes.io/warn":    "privileged",
			"pod-security.kubernetes.io/audit":   "privileged",
		},
	}
	return json.Marshal(ns)
}

// fallbackImageTag is installed whenever the build is not stamped with a
// release version. It is the branch every C8s component publishes; it is
// deliberately not "latest", which cds does not publish (so
// `crane digest ghcr.io/confidential-dot-ai/cds:latest` under --resolve-digests would
// abort with MANIFEST_UNKNOWN).
const fallbackImageTag = "main"

// releaseVersion matches a clean release tag (vMAJOR.MINOR.PATCH), the only
// version for which CI publishes a matching image tag. A `git describe`
// derivative (e.g. v1.2.3-5-gabc, a bare commit SHA, or empty) has no published
// image, so defaultInstallImageTag falls back to fallbackImageTag.
var releaseVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// defaultInstallImageTag picks the image tag for an install: the build version
// when it is a published release tag, otherwise fallbackImageTag.
func defaultInstallImageTag(buildVersion string) string {
	if releaseVersion.MatchString(buildVersion) {
		return buildVersion
	}
	return fallbackImageTag
}

// buildInstallHelmArgs assembles the `helm upgrade --install` argv. Ordering is
// load-bearing: the operator's -f files come first and the computed values file
// LAST, so the CLI's computed values win on the keys they set (helm merges -f
// last-wins) — matching the prior "--set beats -f" precedence. --skip-crds is a
// helm invocation flag (not a value), emitted iff CRDs are skipped.
func buildInstallHelmArgs(chartPath, computedValues string, valueFiles []string, installCRDs, wait bool) []string {
	helmArgs := []string{
		"upgrade", "--install", installRelease, chartPath,
		"--namespace", installNamespace,
	}
	if !installCRDs {
		helmArgs = append(helmArgs, "--skip-crds")
	}
	for _, vf := range valueFiles {
		helmArgs = append(helmArgs, "-f", vf)
	}
	helmArgs = append(helmArgs, "-f", computedValues)
	if wait {
		timeout := "--timeout=5m"
		helmArgs = append(helmArgs, "--wait", timeout)
	}
	return helmArgs
}

// writeComputedValues turns the buildValueArgs --set/--set-string pairs into a
// values.yaml in a tmpfile and returns its path (caller removes it). install
// passes it as a -f instead of shelling a pile of --set flags; the conversion
// is the same one `c8s render-values` uses for its output.
func writeComputedValues(setArgs []string) (string, error) {
	values, err := valueArgsToTree(setArgs)
	if err != nil {
		return "", err
	}
	out, err := yaml.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("marshal computed values: %w", err)
	}
	// Echo the computed values so the install is still legible now that they are
	// a -f file rather than inline --set flags (stderr; helm's own output stays
	// on stdout).
	fmt.Fprintf(os.Stderr, "+ computed values:\n%s", out)
	f, err := os.CreateTemp("", "c8s-install-values-*.yaml")
	if err != nil {
		return "", fmt.Errorf("create computed values file: %w", err)
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write computed values: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("close computed values: %w", err)
	}
	return f.Name(), nil
}

// resolveImageTag returns the tag to resolve component images at: the explicit
// --image-tag when set, otherwise the build-version default. The CLI and its
// component images publish in lockstep, so the default is correct for a normal
// install; --image-tag overrides it to pin a specific branch/tag/release —
// e.g. a fleet promoting `main` from a release-stamped CLI build.
func resolveImageTag() string {
	if installImageTag != "" {
		return installImageTag
	}
	return defaultInstallImageTag(version.Version)
}

// appendInstallCRDArgs emits the value that disables the CRD-dependent
// status-mirror when CRDs are skipped. It returns value args only — the helm
// `--skip-crds` invocation flag is added at the helm call site (install), not
// here, since these args are converted to a values tree and `--skip-crds` is
// not a value.
func appendInstallCRDArgs(setArgs []string, installCRDs bool) []string {
	if installCRDs {
		return setArgs
	}
	return append(setArgs, "--set", "statusMirror.enabled=false")
}

// appendDistroInstallArgs translates the detected host distro into the
// nri-image-policy containerd layout. No enum guard: the value comes from
// chooseDistro, and the chart re-validates anyway.
func appendDistroInstallArgs(helmArgs []string, distro string) []string {
	return append(helmArgs,

		"--set-string", "nriImagePolicy.distro="+distro,
	)
}

// appendCvmModeInstallArgs translates --cvm-mode into the attestation-api
// values. The chart re-validates, so the allowed check is a fast typo guard
// before shelling to helm.
//
// cvm-mode selects which TEE device gets mounted (it does NOT vary the privilege
// level — all modes render privileged: true, since a hostPath device mount alone
// does not grant device-cgroup access):
//
//	node, gke      → native /dev/sev-guest (SEV-SNP) by default, or
//	                 /dev/tdx-guest (Intel TDX) if --hardware-platform tdx
//	aks            → vTPM /dev/tpm0
//
// bare-metal and gke are distinct deployment targets that happen to share the
// native-TEE-device wiring (they are NOT aliases):
//
//	bare-metal → generalized node-as-CVM: our own nodes (bare-metal TDX/SNP,
//	       self-managed) are themselves confidential VMs. Pods run as ordinary
//	       processes attested via the node's own quote. Cloud-agnostic. The node
//	       image bakes attestation-api and nri-image-policy, so both are
//	       disabled here.
//	gke  → GKE specifically: Google's managed confidential VMs.
//
// GKE is the reason a plain managed→vTPM mapping is wrong: GKE confidential VMs
// are a managed cloud but still expose the native /dev/sev-guest ioctl, not a
// vTPM. The chart's teeDevices default is the SNP shape; this flips it as
// needed per (mode, platform). Without it a `--cvm-mode aks` install would
// mount /dev/sev-guest (absent on AKS), and a bare-metal TDX host would
// similarly mount the wrong device — the attestation-api pod would fail the
// hostPath CharDevice check.
//
// `--cvm-mode` (deployment shape) and `--hardware-platform` (CPU TEE) are
// ORTHOGONAL axes. pod/node/gke pair with either SEV-SNP
// (--hardware-platform sev-snp, default) or Intel TDX (--hardware-platform
// tdx). aks uses the Azure vTPM path regardless of the CPU TEE type: the node's
// vTPM HCL report wraps an SNP report on an SEV-SNP CVM (az-snp) or a TD quote
// on an Intel TDX CVM (az-tdx). Both are supported; --hardware-platform tdx on
// aks selects the az-tdx shape (no /dev/tdx-guest needed — the TD quote comes
// from the vTPM), and the mesh/CDS armTLS platform is set to tdx accordingly.
//
// Mixed-hardware inside a single cluster (some SNP hosts, some TDX hosts) is
// out of scope for now — a cluster is one hardware platform. Mixed support
// would want the attestation-api DaemonSet split per-platform with per-node
// label selectors, and armtlsmesh's `--platform` similarly per-node.
// Follow-up work.
//
// aks also opts the pod-injector MutatingWebhookConfiguration out of AKS's
// "admissionsenforcer" controller (annotation admissions.enforcer/disabled),
// which otherwise rewrites the webhook namespaceSelector and makes every helm
// re-apply conflict. That is rendered chart-side off attestationApi.cvmMode (so
// GitOps/HelmRelease installs get it too), not emitted as a --set here; see
// internal/helmchart/c8s/templates/webhook.yaml.
func appendCvmModeInstallArgs(helmArgs []string, cvmMode, hardwarePlatform string) ([]string, error) {
	bakedAttestationAndNRIPlugin, err := deployment.BakedAttestationAndNRIPlugin(cvmMode)
	if err != nil {
		return nil, err
	}
	if err := validateHardwarePlatform(hardwarePlatform); err != nil {
		return nil, err
	}
	helmArgs = append(helmArgs, "--set-string", "attestationApi.cvmMode="+cvmMode)
	// Device wiring:
	//   aks: vTPM (/dev/tpm0) regardless of --hardware-platform. On Azure the
	//        node *is* the CVM and attestation rides the vTPM HCL report, which
	//        wraps either an SNP report (az-snp) or a TD quote (az-tdx). AKS
	//        exposes no /dev/sev-guest or /dev/tdx_guest to the guest, so the
	//        vTPM is the only evidence source for both SNP and TDX aks nodes.
	//   node/gke + --hardware-platform sev-snp: native /dev/sev-guest
	//   node/gke + --hardware-platform tdx:     native /dev/tdx-guest
	sevGuest, tdxGuest, tpm := "false", "false", "false"
	switch {
	case cvmMode == "aks":
		tpm = "true"
	case hardwarePlatform == "tdx":
		tdxGuest = "true"
	default:
		sevGuest = "true"
	}
	helmArgs = append(helmArgs,
		"--set", "attestationApi.teeDevices.sevGuest="+sevGuest,
		"--set", "attestationApi.teeDevices.tdxGuest="+tdxGuest,
		"--set", "attestationApi.teeDevices.tpm="+tpm,
	)
	// Propagate the CPU TEE to CDS, which names its armTLS platform. It
	// defaults to SNP in the chart; on a TDX cluster CDS (which self-warms its
	// serving cert via the attestation-api and is non-privileged, so it cannot
	// probe /dev/tdx_guest to auto-detect) must be told `tdx` explicitly, or it
	// parses the attestation-api's TDX quote as an SNP report and crash-loops
	// ("evidence contains neither attestation_report nor hcl_report"). This
	// holds for the Azure-vTPM TDX shape (aks + tdx, i.e. az-tdx) too: the vTPM
	// HCL report carries a TD quote. cds.armtlsPlatform uses `snp`/`tdx` (both
	// normalize az-tdx -> tdx).
	if hardwarePlatform == "tdx" {
		helmArgs = append(helmArgs, "--set-string", "cds.armtlsPlatform=tdx")
	}
	// The router attestation sidecar is on by default (chart default); --attest=false
	// omits it. When on, it passes this platform straight to the attestation-api
	// as the evidence request, so the value must name the evidence SHAPE, not just
	// the silicon: under aks the evidence is the Azure vTPM HCL report (az-snp /
	// az-tdx), and the bare snp/tdx values would ask for /dev/sev-guest //dev/tdx_guest
	// evidence that Azure CVM nodes cannot produce — every attest-pq/attest-lb call
	// then fails 502 attestation_unavailable. generation is AMD-only (Genoa/Milan/…):
	// az-snp auto-detects it from the report CPUID and TDX has no such concept, so
	// every override blanks it rather than ship the chart-default codename (genoa)
	// for hardware it never checked.
	switch {
	case !installAttestEnabled:
		helmArgs = append(helmArgs, "--set", "router.attest.enabled=false")
	case cvmMode == "aks":
		attestPlatform := "az-snp"
		if hardwarePlatform == "tdx" {
			attestPlatform = "az-tdx"
		}
		helmArgs = append(helmArgs,
			"--set-string", "router.attest.platform="+attestPlatform,
			"--set-string", "router.attest.generation=",
		)
	case hardwarePlatform == "tdx":
		helmArgs = append(helmArgs,
			"--set-string", "router.attest.platform=tdx",
			"--set-string", "router.attest.generation=",
		)
	}
	// node: the node image bakes host attestation-api and nri-image-policy;
	// re-rendering them duplicates the baked pair and the baked fail-closed NRI
	// floor denies the chart copies' own images. The NRI installer does stay
	// on, in its baked form — the pins below are the one thing an image built
	// before this release cannot carry, and the installer is the only path that
	// reaches the baked plugin's config.
	if bakedAttestationAndNRIPlugin {
		helmArgs = append(helmArgs,
			"--set", "attestationApi.enabled=false",
			"--set", "nriImagePolicy.baked=true",
		)
	}
	// --measurements pins the expected launch measurement(s) of this cluster's
	// CVM: every client that dials CDS holds it to that measurement
	// (cds.measurements). The operator supplies M — it is a property of the
	// deployed node image (its manifest.json), known before the cluster runs —
	// so CDS is pinned from first boot rather than accept-any-then-tighten.
	// Empty = no pinning (UNSAFE, the chart default).
	//
	// Parse here, on the shared builder path, so the pinned list is validated
	// and normalized regardless of which command emitted it — and so the fanned
	// list matches exactly what was validated (a blank/whitespace entry, e.g.
	// from a trailing comma, is dropped by the parser, not silently emitted as
	// an empty pin that would disable pinning at that index).
	digests, rtmrs, pinArgs, err := installPins()
	if err != nil {
		return nil, err
	}
	helmArgs = append(helmArgs, pinArgs...)
	// cds.measurements pins the launch measurement CDS presents to the
	// components that dial it. In bare-metal/gke/aks the node IS the CVM, so
	// that is the node image's M.
	for i, m := range digests {
		helmArgs = append(helmArgs,
			"--set-string", fmt.Sprintf("cds.measurements[%d]=%s", i, hex.EncodeToString(m)),
		)
	}
	// --rtmrs completes the TDX pin: the launch measurement (MRTD) covers TDVF
	// firmware alone, and RTMR[1]/[2] are what pin the guest kernel and the
	// command line carrying the dm-verity root hash. Emitted normalized and in
	// index order so the fanned values match what was validated.
	for i, pin := range refvalues.FormatRegisterPins(rtmrs) {
		helmArgs = append(helmArgs, "--set-string", fmt.Sprintf("cds.rtmrs[%d]=%s", i, pin))
	}
	for i, c := range installInventoryCIDRs {
		helmArgs = append(helmArgs,
			"--set-string", fmt.Sprintf("cds.sandboxInventoryCIDRs[%d]=%s", i, c),
		)
	}
	return helmArgs, nil
}

// validateCvmMode enforces that --cvm-mode is set and is a known shape. There
// is no default: an unstated deployment shape could silently mismatch the
// cluster's baked versus chart-provided attestation stack.
func validateCvmMode(cvmMode string) error {
	if cvmMode == "" {
		return fmt.Errorf("--%s is required; one of %s", flagCvmMode, strings.Join(allowedCvmModes, ", "))
	}
	if !slices.Contains(allowedCvmModes, cvmMode) {
		return fmt.Errorf("--%s must be one of %s, got %q", flagCvmMode, strings.Join(allowedCvmModes, ", "), cvmMode)
	}
	return nil
}

// allowedPlatforms is what --hardware-platform takes: the canonical family
// names, which is also what the operator and the chart consume. The alias
// spellings teetypes.ParseFamily accepts are deliberately not taken here —
// node labelling compares this value as written.
var allowedPlatforms = []string{string(teetypes.FamilySNP), string(teetypes.FamilyTDX)}

// validateHardwarePlatform enforces that --hardware-platform is set and known,
// exactly like its sibling --cvm-mode. install checks it first in RunE, before
// anything touches the cluster; appendCvmModeInstallArgs re-checks it on the
// shared builder path so render-values is covered too.
func validateHardwarePlatform(hardwarePlatform string) error {
	if hardwarePlatform == "" {
		return fmt.Errorf("--%s is required; one of %s", flagHardwarePlatform, strings.Join(allowedPlatforms, ", "))
	}
	if !slices.Contains(allowedPlatforms, hardwarePlatform) {
		return fmt.Errorf("--%s must be one of %s, got %q", flagHardwarePlatform, strings.Join(allowedPlatforms, ", "), hardwarePlatform)
	}
	return nil
}

// preflightImagePullSecret reads the Secret --image-pull-secret names (absent
// is reported by checkImagePullSecret, not the kubectl error) and delegates to
// checkImagePullSecret. A kubectl failure other than NotFound aborts: the
// check cannot be made, and the states it guards fail late and opaquely if
// installed blind.
func preflightImagePullSecret(ctx context.Context, namespace, name string) error {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "secret", name, "-n", namespace, "-o", "json").Output()
	if err != nil {
		var ee *exec.ExitError
		// NotFound covers both a missing Secret and a not-yet-created release
		// namespace; either way the Secret is not in the cluster.
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "NotFound") {
			return checkImagePullSecret(nil, namespace, name)
		}
		if errors.As(err, &ee) {
			return fmt.Errorf("kubectl get secret %s -n %s: %w: %s", name, namespace, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("kubectl get secret %s -n %s: %w", name, namespace, err)
	}
	var sec corev1.Secret
	if err := json.Unmarshal(out, &sec); err != nil {
		return fmt.Errorf("parse secret %s/%s: %w", namespace, name, err)
	}
	return checkImagePullSecret(&sec, namespace, name)
}

// checkImagePullSecret validates the Secret --image-pull-secret names
// (sec == nil means it is not in the cluster). The Secret must exist and be a
// registry-credential type: kubelet silently skips a missing pull secret and
// ignores non-registry Secret types, so both states would otherwise surface
// only as ImagePullBackOff after a successful-looking install.
func checkImagePullSecret(sec *corev1.Secret, namespace, name string) error {
	if sec == nil {
		return fmt.Errorf("--image-pull-secret %q: no such Secret in namespace %q. Create it first: kubectl create namespace %s; kubectl create secret docker-registry %s -n %s --docker-server=<registry> --docker-username=<user> --docker-password=<token>", name, namespace, namespace, name, namespace)
	}
	if sec.Type != corev1.SecretTypeDockerConfigJson && sec.Type != corev1.SecretTypeDockercfg {
		return fmt.Errorf("--image-pull-secret %q: Secret has type %q, want %s (or legacy %s) — kubelet ignores other Secret types for image pulls", name, sec.Type, corev1.SecretTypeDockerConfigJson, corev1.SecretTypeDockercfg)
	}
	return nil
}

// preflightOperatorImage verifies the operator image exists in the registry
// before installing, for the path where digest resolution is off
// (--resolve-digests=false). With resolution on, appendResolvedDigestArgs
// already fails fast for every component; without it a missing tag surfaces
// only as ImagePullBackOff after a successful-looking install — and the
// tempting fallback (an older tag like :main) is worse: an operator that
// predates the chart's webhook features silently mis-injects. The operator is
// the one component checked: this path deliberately opted out of full
// resolution, and the operator is the image whose chart coupling bites
// hardest. Best-effort beyond that: crane absent or an auth/network failure
// warns and continues; only a confirmed missing tag aborts.
func preflightOperatorImage(ctx context.Context, components []c8sComponent, tag string) error {
	// The operator's valuePath in c8sComponents is the top-level "image".
	var repo string
	for _, c := range components {
		if c.valuePrefix == "image" {
			repo = c.repository
			break
		}
	}
	if repo == "" {
		return nil
	}
	if !crane.Available() {
		fmt.Fprintf(os.Stderr, "warning: cannot verify operator image %s:%s exists (crane not on PATH); a missing tag surfaces only as ImagePullBackOff after install\n", repo, tag)
		return nil
	}
	if _, err := crane.Digest(ctx, repo+":"+tag); err != nil {
		if crane.IsNotFound(err) {
			return fmt.Errorf("operator image %s:%s is not published — %s: %w", repo, tag, tagCouplingHint(repo), err)
		}
		fmt.Fprintf(os.Stderr, "warning: could not verify operator image %s:%s exists (%v); continuing\n", repo, tag, err)
	}
	return nil
}

// appendSingleNodeInstallArgs collapses the dedicated-CDS-node partition for a
// single-node / single-CVM cluster: an empty cds.node.selector makes every node
// CDS-eligible (worker/pull installer everywhere, no split; the node pulls from
// its co-hosted CDS), and the dedicated-node taint toleration is meaningless
// without it. helm renders =null as an empty value the chart reads as "no
// partition". --set wins over -f, so the flag is authoritative if both are supplied.
func appendSingleNodeInstallArgs(helmArgs []string, singleNode bool) []string {
	if !singleNode {
		return helmArgs
	}
	return append(helmArgs,
		"--set", "cds.node.selector=null",
		"--set", "cds.node.tolerations=null",
	)
}

// appendVolumedInstallArgs turns on the node agent that opens encrypted volumes
// (docs/volumes.md) for --volumes.
func appendVolumedInstallArgs(setArgs []string, volumes bool) []string {
	if !volumes {
		return setArgs
	}
	return append(setArgs, "--set", "volumed.enabled=true")
}

// appendExemptNamespacesInstallArgs defaults image admission to admitting
// kube-system by captured digest on the hosted lanes (see hostedCvmModes),
// where the provider's platform pods are not on the C8s allowlist. Without it a
// default install renders digest-only admission and then restarts containerd to
// register the plugin, which on a self-managed control plane denies the static
// pods and never brings the API server back.
//
// A -f file that writes the key owns it: the computed values are helm's last
// -f, so injecting unconditionally would override an operator's choice.
func appendExemptNamespacesInstallArgs(setArgs []string, cvmMode string, valuesFiles []string) ([]string, error) {
	if !slices.Contains(hostedCvmModes, cvmMode) {
		return setArgs, nil
	}
	set, err := valuesFilesSetExemptNamespaces(valuesFiles)
	if err != nil {
		return nil, err
	}
	if set {
		return setArgs, nil
	}
	return append(setArgs, "--set-string", exemptNamespacesPath+"[0]="+platformExemptNamespace), nil
}

type workloadRef struct {
	kind      string
	name      string
	namespace string
	// port is the router upstream port from the ref's optional :<port> suffix,
	// or 0 when absent. Only consumed for the ref --upstream selects.
	port int
}

type workloadAdoption struct {
	cwID string
	ref  workloadRef
}

func validateWorkloadAdoptionFlags(releaseNamespace string, adoptions []workloadAdoption, wait bool) error {
	if len(adoptions) == 0 {
		return nil
	}
	for _, a := range adoptions {
		if a.ref.namespace == releaseNamespace {
			return fmt.Errorf("--%s cannot target the release namespace %q; that namespace is excluded from c8s workload injection", flagWorkloadRef, releaseNamespace)
		}
	}
	if !wait {
		return fmt.Errorf("--%s requires --wait=true so the c8s webhook is ready before existing workloads roll", flagWorkloadRef)
	}
	return nil
}

// upstreamAddress derives router's upstream from --upstream (a cw id that must
// name an adopted workload): the selected workload's headless-Service FQDN with
// the port from that ref's :<port> suffix appended, so router dials the Service
// the operator provisions. Empty --upstream yields "" (router.upstream.address is
// used as-is).
func upstreamAddress(upstream string, adoptions []workloadAdoption) (string, error) {
	if upstream == "" {
		return "", nil
	}
	for _, a := range adoptions {
		if a.cwID == upstream {
			if a.ref.port == 0 {
				return "", fmt.Errorf("--%s %q names a --%s with no :<port>; add the upstream port to that ref (<cw-id>=<namespace>/<kind>/<name>:<port>)", flagUpstream, upstream, flagWorkloadRef)
			}
			return fmt.Sprintf("%s:%d", webhook.WorkloadServiceFQDN(upstream, a.ref.namespace), a.ref.port), nil
		}
	}
	return "", fmt.Errorf("--%s %q must name a --%s confidential.ai/cw id so router routes to an adopted workload", flagUpstream, upstream, flagWorkloadRef)
}

func collectWorkloadAdoptions(rawRefs []string) ([]workloadAdoption, error) {
	adoptions := make([]workloadAdoption, 0, len(rawRefs))
	for _, raw := range rawRefs {
		cwID, refText, err := parseWorkloadAdoptionRef(raw)
		if err != nil {
			return nil, err
		}
		if err := validateWorkloadID(cwID, flagWorkloadRef); err != nil {
			return nil, err
		}
		ref, err := parseWorkloadRef(refText, flagWorkloadRef)
		if err != nil {
			return nil, err
		}
		adoptions = append(adoptions, workloadAdoption{cwID: cwID, ref: ref})
	}
	return dedupeWorkloadAdoptions(adoptions)
}

func validateWorkloadID(cwID, flagName string) error {
	if webhook.WorkloadServiceName(cwID) == "" {
		return fmt.Errorf("--%s confidential.ai/cw id %q must make c8s-<id> a DNS-1035 label: start with a letter, then lowercase letters, digits, or '-', end alphanumeric, <=63 chars total", flagName, cwID)
	}
	return nil
}

func parseWorkloadAdoptionRef(raw string) (cwID, ref string, err error) {
	cwID, ref, ok := strings.Cut(strings.TrimSpace(raw), "=")
	if !ok || strings.TrimSpace(cwID) == "" || strings.TrimSpace(ref) == "" {
		return "", "", errWorkloadRefFormat(flagWorkloadRef)
	}
	return strings.TrimSpace(cwID), strings.TrimSpace(ref), nil
}

func dedupeWorkloadAdoptions(in []workloadAdoption) ([]workloadAdoption, error) {
	seenByWorkload := map[string]workloadAdoption{}
	seenByCWID := map[string]string{}
	out := make([]workloadAdoption, 0, len(in))
	for _, a := range in {
		key := a.ref.namespace + "/" + a.ref.kind + "/" + a.ref.name
		if existing, ok := seenByWorkload[key]; ok {
			if existing.cwID != a.cwID {
				return nil, fmt.Errorf("workload %s is listed with conflicting confidential.ai/cw ids %q and %q", key, existing.cwID, a.cwID)
			}
			if existing.ref.port != a.ref.port {
				return nil, fmt.Errorf("workload %s is listed with conflicting upstream ports %d and %d", key, existing.ref.port, a.ref.port)
			}
			continue
		}
		// One cw id names one confidential workload: it maps to a single
		// c8s-<id> headless Service whose selector matches every pod carrying
		// the label, so two different workloads under one id would silently
		// share an identity and cross-wire that Service's endpoints.
		if other, ok := seenByCWID[a.cwID]; ok {
			return nil, fmt.Errorf("confidential.ai/cw id %q is assigned to two different workloads %s and %s", a.cwID, other, key)
		}
		seenByWorkload[key] = a
		seenByCWID[a.cwID] = key
		out = append(out, a)
	}
	return out, nil
}

func parseWorkloadRef(ref, flagName string) (workloadRef, error) {
	namespace, rest, ok := strings.Cut(ref, "/")
	if !ok {
		return workloadRef{}, errWorkloadRefFormat(flagName)
	}
	kind, namePort, ok := strings.Cut(rest, "/")
	if !ok || namespace == "" || kind == "" || namePort == "" || strings.Contains(namePort, "/") {
		return workloadRef{}, errWorkloadRefFormat(flagName)
	}
	// The <name> may carry an optional :<port> upstream suffix.
	name, portText, hasPort := strings.Cut(namePort, ":")
	if name == "" {
		return workloadRef{}, errWorkloadRefFormat(flagName)
	}
	port := 0
	if hasPort {
		// strconv.Itoa round-trip rejects non-canonical spellings Atoi would
		// otherwise accept (a leading '+' or sign, or leading zeros).
		p, err := strconv.Atoi(portText)
		if err != nil || strconv.Itoa(p) != portText || len(validation.IsValidPortNum(p)) > 0 {
			return workloadRef{}, fmt.Errorf("--%s port %q in %q must be an integer in 1-65535", flagName, portText, ref)
		}
		port = p
	}
	// namespace and name are DNS-1123 subdomains; reject anything else here so a
	// bad ref fails with a clear message instead of an opaque kubectl error.
	if errs := validation.IsDNS1123Subdomain(namespace); len(errs) > 0 {
		return workloadRef{}, fmt.Errorf("--%s namespace %q is not a valid DNS-1123 subdomain: %s", flagName, namespace, strings.Join(errs, "; "))
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return workloadRef{}, fmt.Errorf("--%s workload name %q is not a valid DNS-1123 subdomain: %s", flagName, name, strings.Join(errs, "; "))
	}
	return workloadRef{kind: normalizeWorkloadKind(kind), name: name, namespace: namespace, port: port}, nil
}

func errWorkloadRefFormat(flagName string) error {
	return fmt.Errorf("--%s must be <cw-id>=<namespace>/<kind>/<name>[:<port>] (kind is any resource exposing a pod template at spec.template, e.g. deployment, statefulset, daemonset, or an operator CRD; :<port> is the router upstream port, required on the --upstream ref)", flagName)
}

// normalizeWorkloadKind canonicalizes the built-in aliases and passes any other
// kind through verbatim for kubectl to resolve. A dotted kind.group form is
// accepted; parseWorkloadRef splits on the first '/', so the group survives.
func normalizeWorkloadKind(kind string) string {
	lower := strings.ToLower(kind)
	switch lower {
	case "deployment", "deploy", "deployments":
		return "deployment"
	case "statefulset", "sts", "statefulsets":
		return "statefulset"
	case "daemonset", "ds", "daemonsets":
		return "daemonset"
	}
	return lower
}

func patchAdoptedWorkload(ctx context.Context, ref workloadRef, workloadID string) error {
	patch, err := confidentialWorkloadPatch(workloadID)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "+ kubectl patch %s %s -n %s --type merge # set pod-template %s=%s\n", ref.kind, ref.name, ref.namespace, webhook.AnnotationWorkload, workloadID)
	kc := exec.CommandContext(ctx, "kubectl", "patch", ref.kind, ref.name, "-n", ref.namespace, "--type", "merge", "-p", string(patch))
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("patch adopted workload %s/%s in namespace %s: %w", ref.kind, ref.name, ref.namespace, err)
	}
	return nil
}

func confidentialWorkloadPatch(workloadID string) ([]byte, error) {
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						webhook.AnnotationWorkload: workloadID,
					},
				},
			},
		},
	}
	return json.Marshal(patch)
}

func adoptedWorkloadImages(ctx context.Context, ref workloadRef) ([]string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", ref.kind, ref.name, "-n", ref.namespace, "-o", "json").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("preflight adopted workload %s/%s in namespace %s: kubectl get failed: %w: %s", ref.kind, ref.name, ref.namespace, err, strings.TrimSpace(string(out)))
	}
	template, err := workloadPodTemplate(out)
	if err != nil {
		return nil, fmt.Errorf("read adopted workload %s/%s in namespace %s: %w", ref.kind, ref.name, ref.namespace, err)
	}
	return podTemplateImages(template), nil
}

// reportAdoptedImages prints the images C8s pins into the NRI allowlist for one
// adopted workload, and flags each image referenced by a mutable tag rather than
// a digest. A tag is a TOCTOU risk: the digest read here (and pinned) can differ
// from what the operator's rollout actually pulls later. An unparseable ref is
// reported verbatim; workloadImageAllowlistEntry rejects it downstream.
func reportAdoptedImages(a workloadAdoption, images []string) {
	fmt.Fprintf(os.Stdout, "+ adopt %s -> %s/%s/%s (%d image(s))\n", a.cwID, a.ref.namespace, a.ref.kind, a.ref.name, len(images))
	for _, image := range images {
		fmt.Fprintf(os.Stdout, "    %s\n", image)
		if !imagePinnedByDigest(image) {
			fmt.Fprintf(os.Stderr, "warning: adopted workload %s image %s is pinned by tag, not digest; the digest resolved now may differ from what the rollout pulls\n", a.cwID, image)
		}
	}
}

// imagePinnedByDigest reports whether an image reference carries an explicit
// digest. An unparseable ref counts as not pinned (its parse fails again,
// fatally, in workloadImageAllowlistEntry).
func imagePinnedByDigest(image string) bool {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return false
	}
	_, pinned := named.(reference.Digested)
	return pinned
}

// workloadPodTemplate reads the pod template at spec.template, which every
// supported kind exposes. A kind without one yields an empty template.
func workloadPodTemplate(data []byte) (corev1.PodTemplateSpec, error) {
	var workload struct {
		Spec struct {
			Template corev1.PodTemplateSpec `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &workload); err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("decode pod template: %w", err)
	}
	return workload.Spec.Template, nil
}

func podTemplateImages(template corev1.PodTemplateSpec) []string {
	seen := map[string]bool{}
	var images []string
	add := func(image string) {
		if image == "" || seen[image] {
			return
		}
		seen[image] = true
		images = append(images, image)
	}
	for _, c := range template.Spec.InitContainers {
		add(c.Image)
	}
	for _, c := range template.Spec.Containers {
		add(c.Image)
	}
	// EphemeralContainers are intentionally skipped: they cannot be set on a
	// workload pod template (only added to a live Pod via the ephemeralcontainers
	// subresource), so a workload read here never carries them.
	return images
}

func appendResolvedWorkloadImageArgs(ctx context.Context, helmArgs []string, images []string) ([]string, error) {
	return buildWorkloadImageArgs(helmArgs, images, func(ref string) (string, error) {
		digest, err := crane.Digest(ctx, ref)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "+ resolved adopted workload image %s -> %s\n", ref, digest)
		return digest, nil
	})
}

// buildWorkloadImageArgs renders one any-argv bootstrapAllowlist.workloads
// entry per adopted image digest, named and shaped as `c8s allowlist add` and
// the chart's own component entries are (pkgallowlist.DigestEntry).
func buildWorkloadImageArgs(helmArgs []string, images []string, resolve func(ref string) (string, error)) ([]string, error) {
	entries := map[string]string{}
	digests := map[string]types.Digest{}
	for _, image := range images {
		digest, ref, err := workloadImageAllowlistEntry(image, resolve)
		if err != nil {
			return nil, err
		}
		if _, ok := entries[digest.String()]; !ok {
			entries[digest.String()] = ref
			digests[digest.String()] = digest
		}
	}
	keys := make([]string, 0, len(entries))
	for digest := range entries {
		keys = append(keys, digest)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ref := entries[key]
		prefix := "nriImagePolicy.bootstrapAllowlist.workloads." + pkgallowlist.DigestEntryName(digests[key], ref) + "."
		helmArgs = append(helmArgs,
			"--set-string", prefix+"label="+ref,
			"--set-string", prefix+"containers[0].digest="+key,
			"--set-string", prefix+"containers[0].image="+ref,
			"--set-string", prefix+"containers[0].command.policy=any",
			"--set-string", prefix+"containers[0].args.policy=any",
		)
	}
	return helmArgs, nil
}

func workloadImageAllowlistEntry(image string, resolve func(ref string) (string, error)) (digest types.Digest, ref string, err error) {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return types.Digest{}, "", fmt.Errorf("parse adopted workload image %q: %w", image, err)
	}
	repo := reference.TrimNamed(named).String()
	raw := ""
	if digested, ok := named.(reference.Digested); ok {
		raw = digested.Digest().String()
	} else if raw, err = resolve(named.String()); err != nil {
		return types.Digest{}, "", err
	}
	// ParseDigest enforces sha256:<64 hex> (NRI allowlist keys must be sha256)
	// and lowercases the hex so the emitted key matches containerd's lookup form.
	parsed, err := types.ParseDigest(raw)
	if err != nil {
		return types.Digest{}, "", fmt.Errorf("adopted workload image %q digest %q is not sha256; NRI allowlist entries must be sha256: %w", image, raw, err)
	}
	return parsed, repo + "@" + parsed.String(), nil
}

// tagCouplingHint explains a missing component image in terms of the C8s
// publish model, so the operator lands on the right knob instead of retrying
// tags. The C8s component images (operator, cds, …) publish in lockstep
// (docker.yml) and the chart+operator ship as a unit. Falling back to a
// mismatched component tag is worse than failing: an operator predating the
// chart's webhook features silently mis-injects.
func tagCouplingHint(repo string) string {
	return fmt.Sprintf("the c8s component images publish in lockstep, so each must exist at the install tag; a mismatched older operator would silently lack webhook features the chart expects. If %s is released on its own cadence rather than with c8s, give its c8sComponents entry a pinnedDigest. Verify with: crane ls %s", repo, repo)
}

// appendResolvedDigestArgs resolves each chart component's repo:tag to its
// registry digest (via crane) and appends the helm --set flags that pin it.
func appendResolvedDigestArgs(ctx context.Context, chartPath string, helmArgs []string, tag string, components []c8sComponent) ([]string, error) {
	if !crane.Available() {
		return nil, fmt.Errorf("digest resolution needs the 'crane' CLI on PATH; install it or pass --resolve-digests=false and supply digests via -f")
	}
	enabled, err := componentEnabledPredicate(ctx, chartPath, helmArgs)
	if err != nil {
		return nil, err
	}
	return buildDigestArgs(helmArgs, tag, components, func(ref string) (string, error) {
		digest, err := crane.Digest(ctx, ref)
		if err != nil {
			return "", err
		}
		// Progress to stderr: render-values writes the values bundle to stdout,
		// so stdout must stay clean. Install's stdout is diagnostic too.
		fmt.Fprintf(os.Stderr, "+ resolved %s -> %s\n", ref, digest)
		return digest, nil
	}, enabled)
}

// componentEnabledPredicate reports the effective enabled value at a component's
// enabledPath, given the chart defaults, the operator's -f values files, and the
// --set overrides assembled so far — in helm's precedence order (defaults < -f
// files in order < --set). Getting the -f files right matters for a component
// that defaults to disabled and is turned on through -f (e.g.
// volumed.enabled): without them the resolver would treat it as off and skip
// pinning its digest, and the render then fails with no image ref. The merged
// tree is built once and shared across the per-component calls.
func componentEnabledPredicate(ctx context.Context, chartPath string, setArgs []string) (func(valuePath string) (bool, error), error) {
	tree, err := effectiveValues(ctx, chartPath, setArgs)
	if err != nil {
		return nil, err
	}
	return func(valuePath string) (bool, error) {
		return boolAtPath(tree, valuePath), nil
	}, nil
}

// effectiveValues resolves the values tree the release will actually render
// with, in helm's precedence order: chart defaults < -f files in order <
// --set. Callers that decide on a value the operator may have overridden (the
// digest resolver, the TEE-node preflight) must read this, not the defaults.
func effectiveValues(ctx context.Context, chartPath string, setArgs []string) (map[string]any, error) {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return nil, fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return nil, fmt.Errorf("parse chart values: %w", err)
	}
	for _, vf := range installValues {
		raw, err := os.ReadFile(vf)
		if err != nil {
			return nil, fmt.Errorf("read values file %q: %w", vf, err)
		}
		var overlay map[string]any
		if err := yaml.Unmarshal(raw, &overlay); err != nil {
			return nil, fmt.Errorf("parse values file %q: %w", vf, err)
		}
		helmchart.MergeValues(tree, overlay)
	}
	if err := overlaySetArgs(tree, setArgs); err != nil {
		return nil, err
	}
	return tree, nil
}

// overlaySetArgs applies the scalar --set/--set-string overrides in setArgs onto
// tree (--set values are type-coerced, --set-string stay strings). --set-file is
// skipped: it names a file and never carries a component enable toggle.
func overlaySetArgs(tree map[string]any, setArgs []string) error {
	for i := 0; i+1 < len(setArgs); i += 2 {
		flag, kv := setArgs[i], setArgs[i+1]
		before, after, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		path, raw := before, after
		var err error
		switch flag {
		case "--set":
			err = setNested(tree, strings.Split(path, "."), coerce(raw, true))
		case "--set-string":
			err = setNested(tree, strings.Split(path, "."), raw)
		}
		if err != nil {
			return fmt.Errorf("overlay %s %s: %w", flag, kv, err)
		}
	}
	return nil
}

// buildDigestArgs appends, for every component, the --set flags that pin both
// its repository and the digest resolved against that repository. Pinning the
// repository too means an operator's -f override of a repository cannot leave
// the chart deploying repoA@<digest-of-repoB>: helm gives --set strict
// precedence over -f, so the repository and digest move together. cds.image
// covers both the CDS Deployment and the allowlist-seed / floor self-entry,
// which all read it. Any resolution failure aborts: a
// partially-pinned floor would let the render guard pass while the served
// allowlist pointed at the wrong digest. The resolver is injected so the arg
// assembly is testable without a registry.
//
// A component carrying a chart-declared pinnedDigest is pinned to it and never
// resolved: it is released on another repository's cadence, so no C8s tag names
// an image of it and resolving one can only fail.
func buildDigestArgs(helmArgs []string, tag string, components []c8sComponent, resolve func(ref string) (string, error), enabled func(valuePath string) (bool, error)) ([]string, error) {
	for _, c := range components {
		// Skip components the effective config disables: they never render, so
		// resolving their tag is pointless and aborts a valid install if that
		// baked-only image (e.g. attestationApi under --cvm-mode=bare-metal) is
		// unpublished at the install tag.
		if c.enabledPath != "" {
			on, err := enabled(c.enabledPath)
			if err != nil {
				return nil, fmt.Errorf("component %s: resolve %s: %w", c.valuePrefix, c.enabledPath, err)
			}
			if !on {
				continue
			}
		}
		repo := c.repository
		digest := c.pinnedDigest
		if digest == "" {
			var err error
			digest, err = resolve(repo + ":" + tag)
			if err != nil {
				if crane.IsNotFound(err) {
					return nil, fmt.Errorf("component %s: image %s:%s is not published — %s: %w", c.valuePrefix, repo, tag, tagCouplingHint(repo), err)
				}
				return nil, err
			}
		} else {
			fmt.Fprintf(os.Stderr, "+ pinned %s@%s (chart pinnedDigest; not resolved at %s)\n", repo, digest, tag)
		}
		helmArgs = append(helmArgs,
			"--set-string", c.valuePrefix+".repository="+repo,
			"--set-string", c.valuePrefix+".digest="+digest,
		)
	}
	// Resolving the component digests is exactly when you want them in the NRI
	// allowlist, so turn on derivation (off by default in the chart; the
	// resolve path enables it).
	helmArgs = append(helmArgs, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true")
	return helmArgs, nil
}

func init() {
	installCmd.Flags().StringVar(&installNamespace, "namespace", "c8s-system", "namespace to install into")
	installCmd.Flags().StringVar(&installRelease, "release", "c8s", "Helm release name")
	installCmd.Flags().StringSliceVarP(&installValues, "values", "f", nil, "values files (repeatable)")
	installCmd.Flags().BoolVar(&installWait, "wait", true, "wait for the release to become ready (helm --wait)")
	installCmd.Flags().BoolVar(&installCRDs, "install-crds", true, "install chart CRDs (false passes helm --skip-crds)")
	installCmd.Flags().Int64Var(&installCertFSGroup, "webhook-cert-fs-group", 65532, "fsGroup for injected certificate volume")
	installCmd.Flags().DurationVar(&installGetCertRenewInterval, "webhook-get-cert-renew-interval", 6*time.Hour, "renewal interval for injected workload certificates")
	installCmd.Flags().Int64Var(&installGetCertRunAsUser, "webhook-get-cert-run-as-user", 65532, "runAsUser for injected get-cert containers")
	installCmd.Flags().Int64Var(&installGetCertRunAsGroup, "webhook-get-cert-run-as-group", 65532, "runAsGroup for injected get-cert containers")
	installCmd.Flags().BoolVar(&installGetCertRunAsNonRoot, "webhook-get-cert-run-as-non-root", true, "set runAsNonRoot for injected get-cert containers")
	installCmd.Flags().BoolVar(&installSingleNode, "single-node", false, "single-node / single-CVM cluster: clear the dedicated-CDS-node selector and taint toleration so every node is CDS-eligible (no role=cds label or dedicated node needed). Sets cds.node.selector={} and cds.node.tolerations=[]")
	installCmd.Flags().BoolVar(&installVolumes, "volumes", false, "serve encrypted volumes (docs/volumes.md): deploy volumed, the node agent that opens a pod's volume devices, and pin its image into the NRI allowlist. Off by default — it runs privileged, with hostPID and a writable bind of the kubelet directory")
	installCmd.Flags().StringSliceVar(&installWorkloadRefs, flagWorkloadRef, nil, "existing workload to adopt as a c8s confidential workload, as <cw-id>=<namespace>/<kind>/<name>[:<port>]; repeatable. Kind is any resource exposing a pod template at spec.template (deployment, statefulset, daemonset, or an operator CRD such as <kind>.<group>). The optional :<port> is the router upstream port, needed on the ref --upstream selects")
	installCmd.Flags().StringVar(&installUpstream, flagUpstream, "", "confidential.ai/cw id of the adopted --workload-ref workload router routes its catch-all to; derives the mesh-wrapped upstream c8s-<id>.<ns>.svc.cluster.local:<port> from that ref's :<port>. Without this or a verified-https router.upstream, router renders no catch-all route until one is attached")
	installCmd.Flags().StringVar(&installCvmMode, flagCvmMode, "", "CVM deployment shape (REQUIRED; orthogonal to --hardware-platform): bare-metal (generalized node-as-CVM: our own TDX/SNP nodes are themselves confidential VMs, pods run as ordinary processes, attestation-api + nri baked into the node image), gke (GKE managed confidential VMs), or aks (vTPM /dev/tpm0). bare-metal/gke/aks are node-as-CVM shapes: the node is one trust domain, so they are single-tenant")
	installCmd.Flags().StringVar(&installHardwarePlatform, flagHardwarePlatform, "", "CPU-level TEE hardware (REQUIRED; orthogonal to --cvm-mode): sev-snp (/dev/sev-guest) or tdx (Intel TDX, /dev/tdx-guest). Under --cvm-mode=aks the CPU TEE rides the Azure vTPM: sev-snp selects az-snp and tdx selects az-tdx (no guest device needed — the report comes from /dev/tpm0)")
	installCmd.Flags().BoolVar(&installResolveDigests, "resolve-digests", true, "resolve each c8s component image tag to its registry digest (via crane), pin it, and add the resolved images to the NRI allowlist (enables deriveComponents). On by default; pass --resolve-digests=false when supplying digests via -f")
	installCmd.Flags().BoolVar(&installAttestEnabled, "attest", true, "deploy the router attestation sidecar serving /.well-known/c8s/ (browser/CLI verification via c8s-verify). On by default; pass --attest=false to omit it")
	installCmd.Flags().StringSliceVar(&installInventoryCIDRs, "node-cidr", nil, "CIDR(s) holding this cluster's sandbox inventories (repeatable/comma-separated): CDS dials an inventory inside them and nowhere else. Under --cvm-mode=bare-metal/gke/aks these are node addresses, which is what stops a workload pointing the sandbox-digests callback at its own pod IP; the default is CDS deriving one host route per node from the live node list, so set a range only when the node network is separate from the pod network")
	installCmd.Flags().StringSliceVar(&installMeasurements, "measurements", nil, "expected hex launch measurement(s) of the CVM CDS runs in (repeatable/comma-separated). Pins cds.measurements, which every client that dials CDS holds it to; empty = no pinning (UNSAFE). Under --cvm-mode=bare-metal/gke/aks this is the node image's manifest.json value")
	cmdsutil.BindImagePolicyFlags(installCmd.Flags(), &installMeasurementsConfig, nil, "pins CDS, mesh and NRI; Helm requires unanchored images with identical RTMR pins; excludes --measurements and --rtmrs")
	installCmd.Flags().StringSliceVar(&installRegisters, "rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> completing --measurements on --hardware-platform=tdx (repeatable/comma-separated). Pins cds.rtmrs: RTMR[1] is the guest kernel, RTMR[2] the command line carrying the dm-verity root hash — without them the measurement pin covers TDVF firmware only. Read the values off a boot you trust; ignored for SNP evidence")
	installCmd.Flags().StringVar(&installImagePullSecret, "image-pull-secret", "", "name of an existing registry-credential Secret (kubernetes.io/dockerconfigjson) in the release namespace; the chart appends it to every component's imagePullSecrets, so all pods can pull the c8s images from an authenticated registry (e.g. a private mirror) from first start. The Secret itself is never created or managed by the install — the install fails fast if it is missing or has the wrong type")
	installCmd.Flags().StringVar(&installImageTag, "image-tag", "", "component image tag to resolve digests at (default: the CLI build version, or 'main' for an unstamped build). Override to pin a specific branch/tag/release")
	installCmd.Flags().StringVar(&installOperatorKeys, "operator-keys", "", "path to a PEM bundle of operator EC public keys that authorize `c8s allowlist` writes; sets cds.operatorKeys. Without it, allowlist writes are disabled (reads still served). See the README \"Operator allowlist credentials\"")
	installCmd.Flags().BoolVar(&installForce, "force", false, "proceed past guarded prompts — currently: install without --operator-keys (allowlist writes disabled), and a fail-closed image policy that would deny the cluster's own platform pods (they do not come back after the containerd restart)")
	rootCmd.AddCommand(installCmd)
}

// withStderr appends the stderr an exec failure captured (Cmd.Output records
// it on ExitError when Cmd.Stderr is unset), so kubectl's own reason reaches
// the operator instead of a bare "exit status 1".
func withStderr(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	return err
}
