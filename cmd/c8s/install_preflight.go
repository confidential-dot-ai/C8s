package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8sversion "k8s.io/apimachinery/pkg/util/version"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

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
