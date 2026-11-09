//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	k8sversion "k8s.io/apimachinery/pkg/util/version"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var (
	installNamespace string
	installRelease   string
	installValues    []string
	installWait      bool

	installPlatform        string
	installVolumes         bool
	installImagePullSecret string
	installOperatorKeys    string
	installForce           bool

	installUpstream     string
	installWorkloadRefs []string

	installChartDir   string
	installCDSAddress string
	installCDSPin     string
	installSeedOut    string
	installPodCIDRs   []string

	// installCDS is the pin this install holds its CDS to, resolved once from
	// the values the release renders with, so the chart, the clients this
	// install dials and the commands it prints name one document.
	installCDS *cdsPin
)

// Flag names referenced in more than one place (registration plus a Changed()
// gate or an arg-builder call). Naming them once keeps the references from
// drifting.
const (
	flagChart            = "chart"
	flagPlatform         = "platform"
	flagHardwarePlatform = "hardware-platform"
	flagWorkloadRef      = "workload-ref"
	flagUpstream         = "upstream"
	flagCDSAddress       = "cds-address"
	flagCDSPin           = "cds-pin"
	flagSeedOut          = "allowlist-seed-out"
	flagPodCIDR          = "pod-cidr"
)

// cloudPlatforms name the cloud chart's stock values files,
// values-<platform>.yaml.
var cloudPlatforms = []string{
	"aks-snp",
	"aks-tdx",
	"gke-snp",
}

// validatePlatform accepts an empty --platform: the -f files then set the
// platform keys the chart requires.
func validatePlatform(platform string) error {
	if platform == "" || slices.Contains(cloudPlatforms, platform) {
		return nil
	}
	return fmt.Errorf("--%s must be one of %s, got %q", flagPlatform, strings.Join(cloudPlatforms, ", "), platform)
}

// orderedValuesFiles are the -f files a release renders with, in helm's
// precedence order: the stock file --platform selects, then the operator's own.
// Install passes this list to everything that reads the values.
func orderedValuesFiles(chartPath, platform string, userFiles []string) []string {
	if platform == "" {
		return userFiles
	}
	stock := filepath.Join(chartPath, "values-"+platform+".yaml")
	return append([]string{stock}, userFiles...)
}

// c8sComponent is a chart image from the component table: the values path of
// its image object and that object's default repository.
type c8sComponent struct {
	valuesPath string
	repository string
}

// componentsFile is c8s-lib's files/components.yaml: the component table the
// chart derives its allowlist from and the router's nginx pin beside it. The
// file's own header states each field's contract.
type componentsFile struct {
	Components  []componentDeclaration `yaml:"components"`
	RouterNginx routerNginxDeclaration `yaml:"routerNginx"`
}

type componentDeclaration struct {
	ValuePath string `yaml:"valuePath"`
}

type routerNginxDeclaration struct {
	Image componentImagePin `yaml:"image"`
}

type componentImagePin struct {
	Repository string `yaml:"repository"`
	Digest     string `yaml:"digest"`
}

// chartComponents reads the component set from the chart at chartPath: the
// table in its c8s-lib files/components.yaml, which the chart's c8s.components
// helper reads too, and each repository from `helm show values` (which dumps
// values.yaml without rendering templates, so no render guard fires).
func chartComponents(ctx context.Context, chartPath string) ([]c8sComponent, error) {
	values, err := chartValues(ctx, chartPath)
	if err != nil {
		return nil, err
	}
	file, err := chartComponentsFile(chartPath)
	if err != nil {
		return nil, err
	}
	return componentsFromFile(file, values)
}

func chartValues(ctx context.Context, chartPath string) (map[string]any, error) {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return nil, fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return nil, fmt.Errorf("parse chart values: %w", err)
	}
	return tree, nil
}

// chartComponentsFile reads the components file of the chart's c8s-lib
// dependency.
func chartComponentsFile(chartPath string) (componentsFile, error) {
	path := filepath.Join(chartPath, helmchart.ComponentsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return componentsFile{}, fmt.Errorf("read %s (build the chart's c8s-lib dependency with `helm dependency build`): %w", path, err)
	}
	var file componentsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return componentsFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return file, nil
}

// componentsFromFile reads the components file's table, each repository from
// its valuePath in the values tree.
func componentsFromFile(components componentsFile, values map[string]any) ([]c8sComponent, error) {
	if len(components.Components) == 0 {
		return nil, fmt.Errorf("chart declares no components")
	}

	comps := make([]c8sComponent, 0, len(components.Components))
	for _, declared := range components.Components {
		if declared.ValuePath == "" {
			return nil, fmt.Errorf("components entry declares no valuePath: %+v", declared)
		}
		repo, err := stringAtPath(values, declared.ValuePath+".repository")
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", declared.ValuePath, err)
		}
		comps = append(comps, c8sComponent{
			valuesPath: declared.ValuePath,
			repository: repo,
		})
	}
	return comps, nil
}

// cdsPreflight refuses an install that names no CDS: no --cds-address and
// --cds-pin, and no -f values file setting cds.address and
// cds.measurementsConfig. The chart fails that render too; this names the
// install flags before anything runs.
func cdsPreflight(address string, pin string, valuesFiles []string) error {
	if cdsNamed(address, pin) {
		return nil
	}
	values, err := cdsValues(valuesFiles)
	if err != nil {
		return err
	}
	named := func(path string) string {
		text, _ := values[path].(string)
		return text
	}
	if cdsNamed(named("cds.address"), named("cds.measurementsConfig")) {
		return nil
	}
	return fmt.Errorf("nothing names the CDS this cluster trusts, so nothing dialing it could tell it from any other attested TEE: pass --%s <ip:port> and --%s <cds-pin.json>, the outputs of `c8s cds config new`", flagCDSAddress, flagCDSPin)
}

// cdsValues are the CDS settings the -f files name, merged as helm merges
// them: the last file writing a path is the one the release renders with.
func cdsValues(valuesFiles []string) (map[string]any, error) {
	values := map[string]any{}
	for _, f := range valuesFiles {
		tree, err := decodeValuesFile(f)
		if err != nil {
			return nil, err
		}
		for _, path := range []string{
			"cds.address",
			"cds.measurementsConfig",
		} {
			if v, ok := valueAtPath(tree, path); ok {
				values[path] = v
			}
		}
	}
	return values, nil
}

// confidentialNodeSelectorKey is the cloud value naming the labels this
// platform puts on a confidential node.
const confidentialNodeSelectorKey = "confidentialNodeSelector"

// confidentialNodeSelector is the chart's confidential-node labels in kubectl
// -l form, so install reasons about the nodes the chart places C8s on. The
// schema requires the labels, so an empty selector never reaches a render.
func confidentialNodeSelector(effectiveValues map[string]any) (string, error) {
	labels, ok := nestedMap(effectiveValues, confidentialNodeSelectorKey)
	if !ok {
		return "", fmt.Errorf("%s is not a map of node labels", confidentialNodeSelectorKey)
	}
	terms := make([]string, 0, len(labels))
	for key, value := range labels {
		text, isText := value.(string)
		if !isText {
			return "", fmt.Errorf("%s.%s must be a label value, got %v", confidentialNodeSelectorKey, key, value)
		}
		terms = append(terms, key+"="+text)
	}
	slices.Sort(terms)
	return strings.Join(terms, ","), nil
}

// confidentialNodes lists the nodes carrying the confidential-node labels, and
// refuses a cluster where none does: the node agents' DaemonSets would want no
// pod, which reads as ready, and the router would sit Pending until `--wait`
// times out.
func confidentialNodes(ctx context.Context, selector string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-l", selector,
		"-o", `jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}`).Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get nodes -l %s: %w", selector, withStderr(err))
	}
	var nodes []string
	for n := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if n = strings.TrimSpace(n); n != "" {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no node carries %s, the labels that mark this cluster's confidential VMs, so every C8s node agent and the router would have nowhere to run: create a confidential node pool carrying them, or set %s to the labels this cluster's confidential nodes carry",
			selector, confidentialNodeSelectorKey)
	}
	return nodes, nil
}

// preflightRouterHostPort fails fast when router's host port is already bound on
// every confidential node, so the router pod would sit Pending and `--wait`
// would time out with an opaque scheduler error. The classic collision is the
// cluster's own ingress controller on host 443.
func preflightRouterHostPort(ctx context.Context, nodes []string) error {
	podsJSON, err := exec.CommandContext(ctx, "kubectl", "get", "pods",
		"--all-namespaces", "-o", "json").Output()
	if err != nil {
		return fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	var list corev1.PodList
	if err := json.Unmarshal(podsJSON, &list); err != nil {
		return fmt.Errorf("parse pod list: %w", err)
	}

	// Ignore the router's namespace: C8s's own router pod lives there, so a
	// re-install (Recreate) does not flag itself.
	if blocked, holders := hostPortConflict(list.Items, nodes, helmchart.RouterHostPort, workloadclaims.RouterNamespace); blocked {
		return fmt.Errorf("router wants host port %d but it is already bound on every confidential node by: %s. "+
			"router would stay Pending and --wait would time out; free the port on at least one node",
			helmchart.RouterHostPort, strings.Join(holders, ", "))
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
// The pods it judges are the confidential nodes' own: the plugin enforces the
// policy there alone.
//
// It also reports to w what an exempt namespace will admit (see
// reportExemptedImages).
//
// --force installs anyway, and returns the same list as a warning.
func preflightImagePolicy(
	ctx context.Context,
	w io.Writer,
	values map[string]any,
	components []c8sComponent,
	releaseNamespace string,
	nodes []string,
	force bool,
) (warn string, err error) {
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
	pods := podsOnNodes(list.Items, nodes)

	exempt := stringsAtPath(values, exemptNamespacesPath)
	reportExemptedImages(w, exempt, exemptedPlatformImages(pods, exempt))

	denied := deniedPlatformImages(pods, releaseNamespace, exempt, admissibleDigests(values, components))
	if len(denied) == 0 {
		return "", nil
	}
	if force {
		return "installing a fail-closed image policy that denies " + deniedSummary(denied) + "; those containers will not come back after the containerd restart", nil
	}
	return "", fmt.Errorf("fail-closed image admission would deny %s the cluster runs, and registering the plugin restarts containerd — the denied containers would not come back:\n  %s\nAdmit their namespaces with -f setting nriImagePolicy.policy.exemptNamespaces, admit their digests with nriImagePolicy.bootstrapAllowlist.workloads entries under any command and args, or re-run with --force to install anyway",
		deniedSummary(denied), strings.Join(denied, "\n  "))
}

func podsOnNodes(pods []corev1.Pod, nodes []string) []corev1.Pod {
	var on []corev1.Pod
	for _, p := range pods {
		if slices.Contains(nodes, p.Spec.NodeName) {
			on = append(on, p)
		}
	}
	return on
}

// deniedSummary names the size of the denied set for a one-line message.
func deniedSummary(denied []string) string {
	if len(denied) == 1 {
		return "1 platform image"
	}
	return fmt.Sprintf("%d platform images", len(denied))
}

// platformImageLines returns one "namespace/pod  <image>" line per
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
				lines = append(lines, fmt.Sprintf("%s/%s  %s", p.Namespace, p.Name, imageReference(st.Image, st.ImageID, digest)))
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
		if isBareDigest(ref) {
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

// imageReference names an image at digest: the bare repository the first
// reference that names one reports it against — the same form
// workloadImageAllowlistEntry writes as an entry's image label — or the digest
// alone where neither reference names a repository.
func imageReference(
	image string,
	imageID string,
	digest string,
) string {
	for _, ref := range []string{image, imageID} {
		ref = strings.TrimPrefix(ref, "docker-pullable://")
		if isBareDigest(ref) {
			continue
		}
		named, err := reference.ParseDockerRef(ref)
		if err != nil {
			continue
		}
		return reference.TrimNamed(named).String() + "@" + digest
	}
	return digest
}

func isBareDigest(ref string) bool {
	return strings.HasPrefix(ref, "sha256:")
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
		if digest, err := stringAtPath(values, c.valuesPath+".digest"); err == nil && digest != "" {
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

// preflightUpstreamContainerd refuses an install whose host image-policy
// installer would reach a confidential node that is not laid out as upstream
// containerd: the installer writes /etc/containerd/config.toml and restarts
// containerd, which such a node neither reads nor runs, leaving its pods
// admitted by nothing. The build-metadata suffix the bundled kubelet stamps
// onto status.nodeInfo.kubeletVersion is the only signal kubectl can see
// without going on-host.
func preflightUpstreamContainerd(ctx context.Context, selector string) error {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-l", selector,
		"-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\n"}{end}`).Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes -l %s: %w", selector, withStderr(err))
	}
	bundled := bundledKubeletNodes(strings.Split(strings.TrimSpace(string(out)), "\n"))
	if len(bundled) == 0 {
		return nil
	}
	return fmt.Errorf("these nodes run a Kubernetes distribution's own containerd, which c8s does not support: %s. Install on nodes running upstream containerd", strings.Join(bundled, ", "))
}

// bundledKubeletNodes returns the nodes of "name\tkubeletVersion" lines whose
// kubelet is a distribution's own build. A line without a tab reports no
// kubelet version and is skipped: an unclassifiable node is not a finding.
func bundledKubeletNodes(lines []string) []string {
	var nodes []string
	for _, l := range lines {
		name, version, ok := strings.Cut(l, "\t")
		if !ok || name == "" {
			continue
		}
		for _, suffix := range []string{"+rke2", "+k3s"} {
			if strings.Contains(version, suffix) {
				nodes = append(nodes, name)
				break
			}
		}
	}
	return nodes
}

// containerdNRIUserVersion is the first containerd that gives NRI plugins a
// container's user (containerd 2.3, containerd/containerd#12769). The
// admission plugin holds a container to the uid its mesh role reserves, so
// below this version it reads every container as uid 0 and refuses it.
var containerdNRIUserVersion = k8sversion.MustParseGeneric("2.3")

// preflightContainerdVersion refuses an install whose confidential nodes
// report a container runtime that gives the admission plugin no container
// user, which it needs to admit any container it gates.
func preflightContainerdVersion(ctx context.Context, selector string) error {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-l", selector,
		"-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}`).Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes -l %s: %w", selector, withStderr(err))
	}
	without := nodesWithoutNRIUser(strings.Split(strings.TrimSpace(string(out)), "\n"))
	if len(without) == 0 {
		return nil
	}
	return fmt.Errorf("these nodes report no containerd %s or later, the first that gives NRI plugins a container's user: %s. Without that user the admission plugin reads every container as uid 0, and refuses the router and every confidential pod", containerdNRIUserVersion, strings.Join(without, ", "))
}

// nodesWithoutNRIUser returns "name (runtime)" for each
// "name\tcontainerRuntimeVersion" line whose runtime gives NRI plugins no
// container user. A line carrying no version is skipped: a node whose kubelet
// has reported no runtime yet is not a finding.
func nodesWithoutNRIUser(lines []string) []string {
	var nodes []string
	for _, l := range lines {
		name, runtimeVersion, _ := strings.Cut(l, "\t")
		if name == "" || runtimeVersion == "" {
			continue
		}
		if !runsContainerdWithNRIUser(runtimeVersion) {
			nodes = append(nodes, fmt.Sprintf("%s (%s)", name, runtimeVersion))
		}
	}
	return nodes
}

// runsContainerdWithNRIUser holds for the runtime versions a node reports when
// it runs containerd from containerdNRIUserVersion on. Another runtime, or a
// version that does not parse, does not.
func runsContainerdWithNRIUser(runtimeVersion string) bool {
	number, isContainerd := strings.CutPrefix(runtimeVersion, "containerd://")
	if !isContainerd {
		return false
	}
	parsed, err := k8sversion.ParseGeneric(number)
	return err == nil && parsed.AtLeast(containerdNRIUserVersion)
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

// materializeStdinValues replaces each "-" entry (helm's -f - idiom) with a
// temp file holding the piped values, so every values consumer — the
// TEE-selector scan, effectiveValues, and helm itself — reads the same
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
		tmp, err := fileutil.WriteTemp("c8s-install-stdin-*.yaml", data)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("write stdin values file: %w", err)
		}
		temps = append(temps, tmp)
		out = append(out, tmp)
	}
	return out, cleanup, nil
}

// exemptNamespacesPath is the image-policy value naming the namespaces
// admitted by captured digest.
const exemptNamespacesPath = "nriImagePolicy.policy.exemptNamespaces"

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install C8s on a cloud cluster of confidential VMs via Helm",
	Long: `Extracts the bundled c8s-cloud chart and runs
'helm upgrade --install' against the current kubeconfig context. --platform
names the cluster's confidential VMs (aks-snp, aks-tdx or gke-snp) and selects
the chart's values-<platform>.yaml, which -f files override; without it the -f
files set the platform's values. Deploys:

  - the install namespace (labeled pod-security=privileged)
  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the ConfidentialWorkload CRD
  - the mutating admission webhook configuration
  - the attestation-api DaemonSet (per-node /attest + /verify)
  - cds.address and cds.measurementsConfig, pointing the cluster at the external
    CDS named by --cds-address and --cds-pin
  - the pod-validating webhook configuration
  - the nri-image-policy and router components

The provider's kube-system pods are not on the c8s allowlist, so the chart
admits them by the digests they run at the plugin's first connect
(nriImagePolicy.policy.exemptNamespaces). The install refuses, before it
touches the cluster, when the resolved policy would deny a platform pod the
cluster is already running:
registering the plugin restarts containerd, and a denied control-plane container
does not come back. --force installs anyway.

A release build pins each component image to the digest the c8s-cloud chart of
its own version carries for the same repository
(oci://ghcr.io/confidential-dot-ai/charts/c8s-cloud), and reads nothing else
from that chart. --chart renders a chart directory instead, with the image digests
or tags it and the -f files set; a build that is not a release needs it.

When the c8s images live in a registry that requires authentication, create a
kubernetes.io/dockerconfigjson Secret in the release namespace and pass
--image-pull-secret <name>: the chart wires it into every component's
imagePullSecrets, so pods authenticate from first start.
This is the cluster-side (kubelet) credential; --workload-ref images resolve
locally via crane and your local docker login.

--volumes deploys volumed, the node agent that opens a pod's encrypted volumes
into its mount namespace (docs/volumes.md).

To adopt already-running workloads, pass --workload-ref <id>=<namespace>/<kind>/<name>[:<port>].
The release namespace is excluded from workload injection, so adopted workloads
must live in a separate namespace. After the chart is ready, install patches each
workload's pod template with confidential.ai/cw=<id>; the rollout then goes
through the c8s webhook and the operator provisions the c8s-<id> headless Service.
Install also writes one
nriImagePolicy.bootstrapAllowlist.workloads entry per adopted workload, named
after its cw id and listing every image of its pod template under any command
and args, with mounts limited to the template's memory-backed emptyDirs (the
webhook refuses a workload container that mounts the cert volume), so image
admission (the host NRI plugin) allows the rollout and CDS stamps the cw id on
the workload's certificate. A template mounting anything else or a subPath, or
requesting c8s secrets or volumes, gets an entry admitting any mounts and a
warning: CDS still names the pod, so a route written to it later
trusts those mounts. For the --upstream workload install refuses instead;
write its entry with 'c8s allowlist'. Install refuses an adoption whose pod another entry of the
seed also describes, since CDS would then name it nothing.

The router routes only by the operator-signed route manifest on CDS, verified
under --operator-keys. Without one the router takes the keys from the pinned
CDS. To front an adopted workload, give its ref the :<port> it serves TLS on,
with its get-cert
certificate, and pass --upstream <id>: install builds a manifest whose every
router.san DNS name routes / to c8s-<id>.<ns>.svc.cluster.local:<port>, verified
as the allowlist entry <id>. With --operator-key (or C8S_OPERATOR_KEY) install
signs it and stores it on CDS once the release is ready, keeping the routes of a
manifest CDS already stores (verified against --operator-keys). Without one, or
when storing fails, it writes the manifest to --routes-out and prints the
'c8s routes add' commands that store the route. Its revision is the later of
the stored one plus one and the current Unix time in seconds, or
--routes-revision. The router answers 503 until a manifest is stored.

Requires the 'helm' and 'kubectl' CLIs on PATH, and 'crane' for a
--workload-ref image named by tag.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validatePlatform(installPlatform); err != nil {
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
		upstream, err := upstreamAddress(installUpstream, adoptions)
		if err != nil {
			return err
		}
		pin, removePin, err := resolveCDSPin(installValues)
		if err != nil {
			return err
		}
		defer removePin()
		installCDS = pin
		installRoutesOutSet, installRoutesMaxAgeSet = cmd.Flags().Changed("routes-out"), cmd.Flags().Changed("routes-max-age")
		if err := preflightUpstreamRoutes(); err != nil {
			return err
		}
		if err := preflightRoutesOut(); err != nil {
			return err
		}
		seedOnly := installSeedOut != ""
		if seedOnly {
			if installCDSAddress != "" || installCDSPin != "" {
				return fmt.Errorf("--%s writes the seed the CDS is configured with, so it runs before --%s and --%s name one", flagSeedOut, flagCDSAddress, flagCDSPin)
			}
		} else if err := cdsPreflight(installCDSAddress, installCDSPin, installValues); err != nil {
			return err
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		if _, err := exec.LookPath("kubectl"); err != nil {
			return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
		}
		adopted := make([]adoptedWorkload, 0, len(adoptions))
		for _, adoption := range adoptions {
			template, err := adoptedWorkloadTemplate(cmd.Context(), adoption.ref)
			if err != nil {
				return err
			}
			reportAdoptedImages(adoption, podTemplateImages(template).all())
			adopted = append(adopted, adoptedWorkload{workloadAdoption: adoption, template: template})
		}

		// The cluster before the registry: an install that cannot reach the
		// cluster it is for says so without first pulling a chart.
		kubeVersion, err := clusterKubeVersion(cmd.Context())
		if err != nil {
			return err
		}
		work, err := os.MkdirTemp("", "c8s-install-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(work)
		chart, err := installChart(cmd.Context(), work)
		if err != nil {
			return err
		}
		valuesFiles := orderedValuesFiles(chart.path, installPlatform, installValues)
		// The computed values reach helm as the last -f, so they win over the
		// operator's files on the keys they set.
		valueArgs, err := buildValueArgs(chart.imagePins)
		if err != nil {
			return err
		}
		setArgs, adoptedEntries, err := appendResolvedWorkloadImageArgs(cmd.Context(), valueArgs, adopted, installUpstream)
		if err != nil {
			return err
		}
		computedValues, err := writeComputedValues(setArgs)
		if err != nil {
			return err
		}
		defer os.Remove(computedValues)
		render := seedRender{
			chart:       chart.path,
			release:     installRelease,
			namespace:   installNamespace,
			kubeVersion: kubeVersion,
			valueFiles:  valuesFiles,
			computed:    computedValues,
		}
		if seedOnly {
			return writeInstallSeed(cmd.Context(), render, installSeedOut)
		}
		helmArgs := buildInstallHelmArgs(chart.path, computedValues, valuesFiles, installWait)

		if installImagePullSecret != "" {
			if err := preflightImagePullSecret(cmd.Context(), installNamespace, installImagePullSecret); err != nil {
				return err
			}
		}

		// The values the release will actually render with (chart defaults + -f
		// + computed), read once and shared by the checks below.
		values, err := effectiveValues(cmd.Context(), chart.path, valuesFiles, setArgs)
		if err != nil {
			return err
		}
		// The nodes this release runs on: the chart places every node agent
		// and the router on the confidential ones, and the checks below read
		// those nodes alone.
		nodeSelector, err := confidentialNodeSelector(values)
		if err != nil {
			return err
		}
		nodes, err := confidentialNodes(cmd.Context(), nodeSelector)
		if err != nil {
			return err
		}

		// Fail fast when router's host port is already taken on every
		// confidential node (e.g. an existing ingress owns 443), which would
		// otherwise wedge `--wait`.
		if err := preflightRouterHostPort(cmd.Context(), nodes); err != nil {
			return err
		}

		if err := checkAdoptedEntries(adoptedEntries, values); err != nil {
			return err
		}
		if err := checkNamedCDS(cmd.Context(), render, installCDS); err != nil {
			return err
		}
		var routes upstreamRoutes
		var cdsURL string
		if upstream != "" {
			hosts, skipped := routeHosts(values, installRelease)
			for _, san := range skipped {
				fmt.Fprintf(os.Stderr, "warning: router.san entry %q cannot be a route manifest host, so --%s routes no requests for it\n", san, flagUpstream)
			}
			if len(hosts) == 0 {
				return fmt.Errorf("--%s needs a DNS name in router.san to route requests for: a route manifest host cannot be a wildcard, an IP address or end in a numeric label", flagUpstream)
			}
			routes = upstreamRoutes{hosts: hosts, address: upstream, workload: installUpstream}
			if cdsURL, err = installCDSURL(values); err != nil {
				return err
			}
		}

		// Fail fast when the policy this install renders would deny the
		// cluster's own platform pods: registering the plugin restarts
		// containerd, and a denied control-plane static pod takes the API
		// server with it. Read-only, so it runs with -f too.
		if warn, err := preflightImagePolicy(cmd.Context(), os.Stdout, values, chart.components, installNamespace, nodes, installForce); err != nil {
			return err
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, "warning: "+warn)
		}

		if err := preflightUpstreamContainerd(cmd.Context(), nodeSelector); err != nil {
			return err
		}

		if err := preflightContainerdVersion(cmd.Context(), nodeSelector); err != nil {
			return err
		}

		// The install ships privileged pods (nri-image-policy and
		// attestation-api), so the namespace is labelled privileged: a
		// CIS-hardened cluster would otherwise reject them at admission.
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
		if upstream != "" {
			if err := deliverUpstreamRoutes(cmd.Context(), os.Stdout, routes, cdsURL, adoptedEntries); err != nil {
				return err
			}
		}

		verifyURL, verifyPin := "https://<cds-address>", "<cds-pin.json>"
		if url, err := installCDSURL(values); err == nil {
			verifyURL = url
		}
		if installCDS != nil {
			verifyPin = installCDS.path
		}
		printVerifyHint(os.Stdout, verifyURL, verifyPin)
		return nil
	},
}

// printVerifyHint names the check a client runs on this cluster's front door.
func printVerifyHint(
	w io.Writer,
	cdsURL string,
	cdsPin string,
) {
	fmt.Fprintln(w, "+ router attestation sidecar enabled; clients verify the front door against the")
	fmt.Fprintln(w, "  node measurements and the mesh anchor:")
	fmt.Fprintln(w, "    c8s verify https://<router> --kind lb --mode attest-lb --image-policy-file <node-pins.json> --mesh-ca mesh-ca.pem")
	fmt.Fprintln(w, "  node-pins.json pins the node images: the nodes of the CDS configuration, or")
	fmt.Fprintln(w, "  'c8s measurements derive' of a node image build, never what the endpoint reports.")
	fmt.Fprintf(w, "  Write the anchor with: c8s cds ca --url %s --image-policy-file %s --out mesh-ca.pem\n", cdsURL, cdsPin)
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

// buildInstallHelmArgs assembles the `helm upgrade --install` argv. Ordering is
// load-bearing: the operator's -f files come first and the computed values file
// LAST, so the CLI's computed values win on the keys they set (helm merges -f
// last-wins) — matching the prior "--set beats -f" precedence.
func buildInstallHelmArgs(chartPath, computedValues string, valueFiles []string, wait bool) []string {
	helmArgs := []string{
		"upgrade", "--install", installRelease, chartPath,
		"--namespace", installNamespace,
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

// writeComputedValues turns the computed --set/--set-string pairs into a
// values.yaml in a tmpfile and returns its path (caller removes it). install
// passes it as a -f instead of shelling a pile of --set flags.
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
	path, err := fileutil.WriteTemp("c8s-install-values-*.yaml", out)
	if err != nil {
		return "", fmt.Errorf("write computed values: %w", err)
	}
	return path, nil
}

// allowedPlatforms is what --hardware-platform takes: the canonical family
// names, which is also what the operator and the chart consume. The alias
// spellings teetypes.ParseFamily accepts are deliberately not taken here —
// node labelling compares this value as written.
var allowedPlatforms = []string{string(teetypes.FamilySNP), string(teetypes.FamilyTDX)}

// validateHardwarePlatform enforces that the worker commands'
// --hardware-platform is set and known.
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

// appendVolumedInstallArgs turns on the node agent that opens encrypted volumes
// (docs/volumes.md) for --volumes.
func appendVolumedInstallArgs(setArgs []string, volumes bool) []string {
	if !volumes {
		return setArgs
	}
	return append(setArgs, "--set", "volumed.enabled=true")
}

type workloadRef struct {
	kind      string
	name      string
	namespace string
	// port is the TLS port from the ref's optional :<port> suffix, or 0 when
	// absent. Only consumed for the ref --upstream selects.
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
	uninjected := []string{releaseNamespace, workloadclaims.RouterNamespace}
	for _, a := range adoptions {
		if slices.Contains(uninjected, a.ref.namespace) {
			return fmt.Errorf("--%s cannot target %q; that namespace is excluded from c8s workload injection", flagWorkloadRef, a.ref.namespace)
		}
	}
	if !wait {
		return fmt.Errorf("--%s requires --wait=true so the c8s webhook is ready before existing workloads roll", flagWorkloadRef)
	}
	return nil
}

// upstreamAddress derives the --upstream route's backend address from the
// adopted workload it names: its headless-Service FQDN with the port from that
// ref's :<port> suffix, so the router dials the Service the operator
// provisions. Empty --upstream yields "".
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
	return fmt.Errorf("--%s must be <cw-id>=<namespace>/<kind>/<name>[:<port>] (kind is any resource exposing a pod template at spec.template, e.g. deployment, statefulset, daemonset, or an operator CRD; :<port> is the TLS port the router dials, required on the --upstream ref)", flagName)
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

func adoptedWorkloadTemplate(ctx context.Context, ref workloadRef) (corev1.PodTemplateSpec, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", ref.kind, ref.name, "-n", ref.namespace, "-o", "json").CombinedOutput()
	if err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("preflight adopted workload %s/%s in namespace %s: kubectl get failed: %w: %s", ref.kind, ref.name, ref.namespace, err, strings.TrimSpace(string(out)))
	}
	template, err := workloadPodTemplate(out)
	if err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("read adopted workload %s/%s in namespace %s: %w", ref.kind, ref.name, ref.namespace, err)
	}
	return template, nil
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

// podImages are a pod template's images, init and main containers apart: a
// declared init container may have exited, so an allowlist entry must list it
// as one or a pod past its init phase would not match it.
type podImages struct {
	Init []string
	Main []string
}

// all returns every image once, init containers first.
func (p podImages) all() []string {
	return append(slices.Clone(p.Init), p.Main...)
}

func podTemplateImages(template corev1.PodTemplateSpec) podImages {
	var images podImages
	seen := map[string]bool{}
	// Main first: an image that also runs as an init container is declared
	// once, as a main, which admits it in both roles.
	for _, c := range template.Spec.Containers {
		if c.Image != "" && !seen[c.Image] {
			seen[c.Image] = true
			images.Main = append(images.Main, c.Image)
		}
	}
	for _, c := range template.Spec.InitContainers {
		if c.Image != "" && !seen[c.Image] {
			seen[c.Image] = true
			images.Init = append(images.Init, c.Image)
		}
	}
	// EphemeralContainers are intentionally skipped: they cannot be set on a
	// workload pod template (only added to a live Pod via the ephemeralcontainers
	// subresource), so a workload read here never carries them.
	return images
}

// adoptedWorkload is one --workload-ref with its pod template.
type adoptedWorkload struct {
	workloadAdoption
	template corev1.PodTemplateSpec
}

// injectedMountRules lists the container's memory-backed emptyDir destinations.
func injectedMountRules(template corev1.PodTemplateSpec, c corev1.Container) ([]string, error) {
	for _, a := range []string{webhook.AnnotationSecrets, webhook.AnnotationVolumes} {
		if template.Annotations[a] != "" {
			return nil, fmt.Errorf("it requests %s, whose injected mounts install does not model", a)
		}
	}
	certVolume := webhook.CertVolumeName
	volumes := map[string]corev1.Volume{}
	for _, v := range template.Spec.Volumes {
		volumes[v.Name] = v
	}
	var dests []string
	for _, m := range c.VolumeMounts {
		v, ok := volumes[m.Name]
		switch {
		case m.SubPath != "" || m.SubPathExpr != "":
			return nil, fmt.Errorf("container %s mounts a subPath of volume %s at %s, which the node observes as a data mount", c.Name, m.Name, m.MountPath)
		case !ok && m.Name == certVolume:
		case !ok:
			return nil, fmt.Errorf("container %s mounts undeclared volume %s", c.Name, m.Name)
		case v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory:
			return nil, fmt.Errorf("container %s mounts volume %s at %s, which is not a memory-backed emptyDir", c.Name, m.Name, m.MountPath)
		}
		dests = append(dests, path.Clean(m.MountPath))
	}
	sort.Strings(dests)
	return dests, nil
}

// adoptedEntry is the allowlist entry install writes for one adopted workload
// and the pod CDS matches it against once the pod runs: its main containers
// and native sidecars, with the mounts the node observes. A completed init
// container is not in pod; the entry declares it, so it may be absent.
type adoptedEntry struct {
	workload pkgallowlist.Workload
	pod      []pkgallowlist.RunningContainer
}

func appendResolvedWorkloadImageArgs(ctx context.Context, helmArgs []string, workloads []adoptedWorkload, upstream string) ([]string, map[string]adoptedEntry, error) {
	return buildWorkloadImageArgs(helmArgs, workloads, upstream, os.Stderr, func(ref string) (string, error) {
		digest, err := crane.Digest(ctx, ref)
		if err != nil {
			return "", err
		}
		return digest, nil
	})
}

// buildWorkloadImageArgs renders one bootstrapAllowlist.workloads entry per
// adopted workload, named after its cw id and declaring every container of its
// pod template, in its own role, under any command, args and env. Mounts are
// exact: each container may mount only what the injected pod mounts
// (injectedMountRules), so a host that adds a hostPath over the app's code or
// config gets no admission and no name. Containers with the same image and
// mounts are declared once; an init container also run as a main is admitted
// by the main. One entry for the whole container set is what lets CDS match a
// multi-container pod and stamp the cw id on its leaf, which a workload route
// backend requires (route policy B1).
//
// A workload whose mounts cannot be modelled exactly is refused when it is the
// upstream cw id; any other gets an entry admitting any mounts, a warning on
// warn, and no entry in the returned map.
func buildWorkloadImageArgs(helmArgs []string, workloads []adoptedWorkload, upstream string, warn io.Writer, resolve func(ref string) (string, error)) ([]string, map[string]adoptedEntry, error) {
	entries := map[string]adoptedEntry{}
	for _, w := range workloads {
		prefix := "nriImagePolicy.bootstrapAllowlist.workloads." + w.cwID + "."
		label := w.ref.namespace + "/" + w.ref.kind + "/" + w.ref.name
		helmArgs = append(helmArgs, "--set-string", prefix+"label="+label)
		e := adoptedEntry{workload: pkgallowlist.Workload{Label: label}}
		containers := slices.Concat(w.template.Spec.Containers, w.template.Spec.InitContainers)
		mounts := make([][]string, len(containers))
		exact := true
		for i, c := range containers {
			if c.Image == "" {
				continue
			}
			var err error
			if mounts[i], err = injectedMountRules(w.template, c); err != nil {
				if w.cwID == upstream {
					return nil, nil, fmt.Errorf("adopted workload %s: %w; install cannot write its allowlist entry, so write one named %q yourself (c8s allowlist)", w.cwID, err, w.cwID)
				}
				fmt.Fprintf(warn, "warning: adopted workload %s: %v; install writes its allowlist entry with any mounts, so a route to it trusts those mounts\n", w.cwID, err)
				exact = false
				break
			}
		}
		mains := len(w.template.Spec.Containers)
		for i, c := range containers {
			if c.Image == "" {
				continue
			}
			digest, ref, err := workloadImageAllowlistEntry(c.Image, resolve)
			if err != nil {
				return nil, nil, err
			}
			declared := adoptedContainer(digest, ref, mounts[i], exact)
			init := i >= mains
			if !init || c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				e.pod = append(e.pod, observedContainer(digest, mounts[i]))
			}
			same := func(o pkgallowlist.Container) bool {
				return o.Digest == declared.Digest && slices.Equal(o.Mounts.Rules, declared.Mounts.Rules)
			}
			if slices.ContainsFunc(e.workload.Containers, same) || init && slices.ContainsFunc(e.workload.InitContainers, same) {
				continue
			}
			field, list := "containers", &e.workload.Containers
			if init {
				field, list = "initContainers", &e.workload.InitContainers
			}
			helmArgs = append(helmArgs, containerArgs(fmt.Sprintf("%s%s[%d].", prefix, field, len(*list)), declared)...)
			*list = append(*list, declared)
		}
		if exact {
			entries[w.cwID] = e
		}
	}
	return helmArgs, entries, nil
}

// adoptedContainer declares digest under any command, args and env. With
// exact, it mounts exactly the memory-backed emptyDirs at dests; without, any
// mounts.
func adoptedContainer(digest types.Digest, ref string, dests []string, exact bool) pkgallowlist.Container {
	c := pkgallowlist.Container{
		Digest:  digest,
		Image:   ref,
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Env:     pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyAny},
	}
	if exact && len(dests) == 0 {
		c.Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}
	} else if exact {
		rules := make([]pkgallowlist.MountRule, 0, len(dests))
		for _, dest := range dests {
			rules = append(rules, pkgallowlist.MountRule{Destination: dest, Kind: pkgallowlist.MountEmptyDir})
		}
		c.Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyExact, Rules: rules}
	} else {
		c.Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyAny}
	}
	return c
}

// observedContainer is digest running with the memory-backed emptyDirs at
// dests, as the node reports it. Its argv is unknown to install.
func observedContainer(digest types.Digest, dests []string) pkgallowlist.RunningContainer {
	mounts := []pkgallowlist.ObservedMount{}
	for _, dest := range dests {
		mounts = append(mounts, pkgallowlist.ObservedMount{Destination: dest, Class: pkgallowlist.MountEmptyDir, Storage: pkgallowlist.MountMemory})
	}
	return pkgallowlist.RunningContainer{Digest: digest.String(), Argv: []string{}, Mounts: mounts}
}

func containerArgs(key string, c pkgallowlist.Container) []string {
	args := []string{
		"--set-string", key + "digest=" + c.Digest.String(),
		"--set-string", key + "image=" + c.Image,
		"--set-string", key + "command.policy=any",
		"--set-string", key + "args.policy=any",
		"--set-string", key + "env.policy=any",
	}
	if c.Mounts.Policy != "" {
		args = append(args, "--set-string", key+"mounts.policy="+c.Mounts.Policy)
	}
	for i, r := range c.Mounts.Rules {
		rule := fmt.Sprintf("%smounts.rules[%d].", key, i)
		args = append(args, "--set-string", rule+"destination="+r.Destination, "--set-string", rule+"kind="+string(r.Kind))
	}
	return args
}

// describers returns, sorted, the entries that describe pod once their
// command, args and env admit any: install cannot see the pod's argv or env,
// so an entry admitting its images and mounts under some argv counts.
func describers(workloads map[string]pkgallowlist.Workload, pod []pkgallowlist.RunningContainer) []string {
	var names []string
	for name, w := range workloads {
		if anyProcess(w).Diff(pod).Describes() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// checkAdoptedEntries refuses an adopted workload whose pod another entry of
// the seed this install renders also describes. CDS would then match neither,
// the pod's leaf would carry no workload name, and the router would refuse it
// as a workload backend. The seed is the chart's own (seedWorkloads).
func checkAdoptedEntries(adopted map[string]adoptedEntry, values map[string]any) error {
	if len(adopted) == 0 {
		return nil
	}
	seed, err := seedWorkloads(values)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(adopted)) {
		names := describers(seed, adopted[name].pod)
		if !slices.Contains(names, name) {
			return fmt.Errorf("the allowlist entry %s does not describe the pod of adopted workload %s; drop the -f entry of that name", name, name)
		}
		if others := slices.DeleteFunc(names, func(n string) bool { return n == name }); len(others) > 0 {
			return fmt.Errorf("adopted workload %s runs only images and mounts that allowlist entries %s also admit, so CDS cannot tell which entry names its pod and stamps none; give it an image of its own", name, strings.Join(others, ", "))
		}
	}
	return nil
}

// seedWorkloads mirrors the chart's c8s.allowlistSeedJSON from the values it
// renders, less the entries that pin their command lines: the
// bootstrapAllowlist.workloads entries. A component entry pins its command,
// args and mount table (c8s.podShapes), so it describes only the component's
// own pod.
func seedWorkloads(values map[string]any) (map[string]pkgallowlist.Workload, error) {
	seed := map[string]pkgallowlist.Workload{}
	workloads, _ := nestedMap(values, "nriImagePolicy", "bootstrapAllowlist", "workloads")
	for name, raw := range workloads {
		data, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		w, err := pkgallowlist.ParseWorkloadJSON(data)
		if err != nil {
			return nil, fmt.Errorf("nriImagePolicy.bootstrapAllowlist.workloads.%s: %w", name, err)
		}
		seed[name] = *w
	}
	return seed, nil
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

// effectiveValues resolves the values tree the release will actually render
// with, in helm's precedence order: chart defaults < -f files in order <
// --set. Callers that decide on a value the operator may have overridden must
// read this, not the defaults.
func effectiveValues(
	ctx context.Context,
	chartPath string,
	valuesFiles []string,
	setArgs []string,
) (map[string]any, error) {
	tree, err := chartValues(ctx, chartPath)
	if err != nil {
		return nil, err
	}
	for _, vf := range valuesFiles {
		overlay, err := decodeValuesFile(vf)
		if err != nil {
			return nil, err
		}
		helmchart.MergeValues(tree, overlay)
	}
	// The computed values reach helm as the last -f file, which replaces
	// lists rather than merging their elements.
	computed, err := valueArgsToTree(setArgs)
	if err != nil {
		return nil, err
	}
	return helmchart.MergeValues(tree, computed), nil
}

func init() {
	installCmd.Flags().StringVar(&installNamespace, "namespace", "c8s-system", "namespace to install into")
	installCmd.Flags().StringVar(&installRelease, "release", "c8s", "Helm release name")
	installCmd.Flags().StringSliceVarP(&installValues, "values", "f", nil, "values files (repeatable)")
	installCmd.Flags().BoolVar(&installWait, "wait", true, "wait for the release to become ready (helm --wait)")
	installCmd.Flags().BoolVar(&installVolumes, "volumes", false, "serve encrypted volumes (docs/volumes.md): deploy volumed, the node agent that opens a pod's volume devices, and pin its image into the NRI allowlist. Off by default — it runs privileged, with hostPID and a writable bind of the kubelet directory")
	installCmd.Flags().StringSliceVar(&installWorkloadRefs, flagWorkloadRef, nil, "existing workload to adopt as a c8s confidential workload, as <cw-id>=<namespace>/<kind>/<name>[:<port>]; repeatable. Kind is any resource exposing a pod template at spec.template (deployment, statefulset, daemonset, or an operator CRD such as <kind>.<group>). The optional :<port> is the port the workload serves TLS on with its get-cert certificate, needed on the ref --upstream selects")
	installCmd.Flags().StringVar(&installUpstream, flagUpstream, "", "confidential.ai/cw id of the adopted --workload-ref workload to route / to: writes a route manifest naming c8s-<id>.<ns>.svc.cluster.local:<port> (that ref's :<port>, serving TLS on its get-cert certificate) and the allowlist entry <id>, for every router.san DNS name")
	installCmd.Flags().StringVar(&installOperatorKey, flagOperatorKey, "", "operator EC private key PEM (env "+cdsconn.EnvOperatorKey+") that signs the --upstream route manifest; install then stores it on CDS, pinned by --cds-pin. Without it the manifest goes to --routes-out. Requires --upstream")
	installCmd.Flags().StringVar(&installRoutesOut, "routes-out", "routes.json", "file the --upstream route manifest is written to when no --operator-key signs it, or when install cannot store it on CDS")
	installCmd.Flags().Uint64Var(&installRoutesRevision, "routes-revision", 0, "revision of the --upstream route manifest, above the one CDS stores; default the later of the stored revision plus one and the current Unix time. After a CDS reset, pass one above the highest revision any router applied")
	installCmd.Flags().DurationVar(&installRoutesMaxAge, "routes-max-age", 24*time.Hour, "maxAgeSeconds of a new --upstream route manifest: how long the router admits new attested sessions by it without a successful fetch from CDS; application routing goes on regardless. A manifest CDS already stores keeps its own")
	installCmd.Flags().StringVar(&installPlatform, flagPlatform, "", "the cluster's confidential VMs: aks-snp and aks-tdx (Azure, evidence from the vTPM), or gke-snp (GKE, evidence from the SNP report). Selects the chart's values-<platform>.yaml; without it the -f files set the platform's values")
	installCmd.Flags().StringVar(&installChartDir, flagChart, "", "chart directory to render instead of the bundled chart, with the component images it and the -f files set; required for a build that is not a release")
	installCmd.Flags().StringVar(&installCDSAddress, flagCDSAddress, "", "<host>:<port> of the CDS this cluster trusts, the host a DNS name or an IPv4 address: the VM 'c8s cds config new' wrote a configuration and a pin for. Sets cds.address, which every client of this cluster dials and whose port is the only one their packet rules admit outside the cluster")
	installCmd.Flags().StringVar(&installCDSPin, flagCDSPin, "", "path to that CDS's pin document (cds-pin.json): the image and launch file its VM proves. Sets cds.measurementsConfig, which every client holds the CDS to")
	installCmd.Flags().StringArrayVar(&installPodCIDRs, flagPodCIDR, nil, "a range this cluster assigns pod addresses from, the one 'c8s cds config new --pod-cidr' names; repeatable. The CDS's node subnets are checked against these ranges and the ones the nodes publish, and every pod must answer inside them")
	installCmd.Flags().StringVar(&installSeedOut, flagSeedOut, "", "write the component allowlist entries this install needs served to <file> and stop, changing nothing in the cluster: it reads the cluster's Kubernetes version, so the seed matches the render this install applies. The input 'c8s cds config new --allowlist-seed' takes before the CDS this install then names exists")
	installCmd.Flags().StringVar(&installImagePullSecret, "image-pull-secret", "", "name of an existing registry-credential Secret (kubernetes.io/dockerconfigjson) in the release namespace; the chart appends it to every component's imagePullSecrets, so all pods can pull the c8s images from an authenticated registry (e.g. a private mirror) from first start. The Secret itself is never created or managed by the install — the install fails fast if it is missing or has the wrong type")
	installCmd.Flags().StringVar(&installOperatorKeys, "operator-keys", "", "path to a PEM bundle of operator EC public keys the router verifies route manifests under; sets cds.operatorKeys. Without it the router uses the keys the pinned CDS serves. CDS's own write keys come from 'c8s cds config new --operator-keys'")
	installCmd.Flags().BoolVar(&installForce, "force", false, "install despite a fail-closed image policy that would deny the cluster's own platform pods (they do not come back after the containerd restart)")
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
