package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"strings"

	"github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
)

// policyModeFailClosed is the image-policy mode that denies. In `audit` the
// plugin logs the would-be denial and creates the container anyway.
const policyModeFailClosed = "fail-closed"

// deniedImagesListed caps the images the refusal prints; the rest are counted.
const deniedImagesListed = 20

func confidentialNodePods(ctx context.Context, nodes []string) ([]corev1.Pod, error) {
	podsJSON, err := exec.CommandContext(ctx, "kubectl", "get", "pods",
		"--all-namespaces", "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	var list corev1.PodList
	if err := json.Unmarshal(podsJSON, &list); err != nil {
		return nil, fmt.Errorf("parse pod list: %w", err)
	}
	return podsOnNodes(list.Items, nodes), nil
}

// preflightImagePolicy refuses an install whose rendered image policy would
// deny the cluster's own platform pods. Registering the plugin restarts
// containerd, which recreates those containers under the new policy: on a
// self-managed control plane the static pods are denied and the API server
// never returns, leaving nothing but out-of-band root to recover with.
//
// It reads the EFFECTIVE values (chart defaults + -f + computed), so it runs on
// every install including -f ones — whoever wrote the policy, a cluster whose
// own pods it denies is broken the same way.
//
// It also reports to w the denied containers the cluster survives without (see
// reportDeniedWorkloads).
//
// --force installs anyway, and returns the same list as a warning.
func preflightImagePolicy(
	w io.Writer,
	values map[string]any,
	components []c8sComponent,
	releaseNamespace string,
	pods []corev1.Pod,
	force bool,
) (warn string, err error) {
	// A mode the chart cannot read is the render guard's to reject, not this
	// preflight's; either way nothing is denied here.
	if mode, err := stringAtPath(values, "nriImagePolicy.policy.mode"); err != nil || mode != policyModeFailClosed {
		return "", nil
	}

	exempt := exemptRepositories(values)
	admitted := admissibleDigests(values, components)
	reportExemptedImages(w, exempt, exemptNamespaceImages(pods, exempt))
	reportDeniedWorkloads(w, deniedWorkloadImages(pods, releaseNamespace, exempt, admitted))

	denied := deniedPlatformImages(pods, releaseNamespace, exempt, admitted)
	if len(denied) == 0 {
		return "", nil
	}
	if force {
		return "installing a fail-closed image policy that denies " + deniedSummary(denied) + "; those containers will not come back after the containerd restart", nil
	}
	return "", fmt.Errorf("fail-closed image admission would deny %s the cluster runs, and registering the plugin restarts containerd — the denied containers would not come back:\n  %s\nAdmit a provider namespace by listing it in %s with its image repositories in %s, admit a digest with nriImagePolicy.bootstrapAllowlist.workloads entries under any command and args, or re-run with --force to install anyway",
		deniedSummary(denied), strings.Join(denied, "\n  "), exemptNamespacesPath, exemptRepositoriesPath)
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

type runningImage struct {
	namespace string
	pod       string
	reference string
	digest    string
}

func (i runningImage) line() string {
	return fmt.Sprintf("%s/%s  %s", i.namespace, i.pod, i.reference)
}

// An exited init container is visited: the next start of its pod runs it again.
func restartedContainers(pods []corev1.Pod, visit func(pod corev1.Pod, status corev1.ContainerStatus)) {
	for _, p := range pods {
		if isTerminalPod(p) {
			continue
		}
		for _, status := range podContainerStatuses(p) {
			visit(p, status)
		}
	}
}

// One entry per (namespace, digest): a DaemonSet runs the same image on every
// node.
func runningImages(pods []corev1.Pod, accept func(pod corev1.Pod, image runningImage) bool) []runningImage {
	type namespaceDigest struct{ namespace, digest string }
	seen := map[namespaceDigest]bool{}
	var images []runningImage
	restartedContainers(pods, func(pod corev1.Pod, status corev1.ContainerStatus) {
		digest := imageDigest(status.ImageID, status.Image)
		if digest == "" {
			return
		}
		image := runningImage{
			namespace: pod.Namespace,
			pod:       pod.Name,
			reference: imageReference(status.Image, status.ImageID, digest),
			digest:    digest,
		}
		if !accept(pod, image) {
			return
		}
		key := namespaceDigest{pod.Namespace, digest}
		if seen[key] {
			return
		}
		seen[key] = true
		images = append(images, image)
	})
	slices.SortFunc(images, func(a, b runningImage) int { return strings.Compare(a.line(), b.line()) })
	return images
}

func imageLines(images []runningImage) []string {
	lines := make([]string, 0, len(images))
	for _, image := range images {
		lines = append(lines, image.line())
	}
	return lines
}

func isTerminalPod(p corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

// deniedImage reports whether neither the namespace's exemption nor the
// allowlist admits the image.
func deniedImage(
	image runningImage,
	releaseNamespace string,
	exempt nriimagepolicy.ExemptRepositories,
	admitted map[string]bool,
) bool {
	return image.namespace != releaseNamespace &&
		!exempt.Admits(image.namespace, image.reference) &&
		!admitted[image.digest]
}

func deniedPlatformImages(pods []corev1.Pod, releaseNamespace string, exempt nriimagepolicy.ExemptRepositories, admitted map[string]bool) []string {
	return cappedImageLines(runningImages(pods, func(pod corev1.Pod, image runningImage) bool {
		return platformPod(pod) && deniedImage(image, releaseNamespace, exempt, admitted)
	}))
}

func deniedWorkloadImages(pods []corev1.Pod, releaseNamespace string, exempt nriimagepolicy.ExemptRepositories, admitted map[string]bool) []string {
	return cappedImageLines(runningImages(pods, func(pod corev1.Pod, image runningImage) bool {
		return !platformPod(pod) && deniedImage(image, releaseNamespace, exempt, admitted)
	}))
}

func cappedImageLines(images []runningImage) []string {
	lines := imageLines(images)
	if len(lines) > deniedImagesListed {
		rest := len(lines) - deniedImagesListed
		lines = append(lines[:deniedImagesListed:deniedImagesListed], fmt.Sprintf("… and %d more", rest))
	}
	return lines
}

// A prefix set under a namespace the policy does not exempt admits nothing,
// on a node or here.
func exemptRepositories(values map[string]any) nriimagepolicy.ExemptRepositories {
	prefixesByNamespace, _ := nestedMap(values, strings.Split(exemptRepositoriesPath, ".")...)
	exempt := nriimagepolicy.ExemptRepositories{}
	for _, namespace := range stringsAtPath(values, exemptNamespacesPath) {
		exempt[namespace] = stringList(prefixesByNamespace[namespace])
	}
	return exempt
}

// Every pod of the namespace counts, whatever created it.
func exemptNamespaceImages(pods []corev1.Pod, exempt nriimagepolicy.ExemptRepositories) []runningImage {
	return runningImages(pods, func(pod corev1.Pod, image runningImage) bool {
		return exempt.Admits(pod.Namespace, image.reference)
	})
}

func reportDeniedWorkloads(w io.Writer, images []string) {
	if len(images) == 0 {
		return
	}
	fmt.Fprint(w, "+ image policy: these running containers are not admitted, and no platform pod\n"+
		"  runs them. Registering the plugin stops them, and admission refuses them after\n"+
		"  that:\n")
	for _, image := range images {
		fmt.Fprintf(w, "    %s\n", image)
	}
	fmt.Fprintf(w, "  Admit their digests with nriImagePolicy.bootstrapAllowlist.workloads entries\n"+
		"  under any command and args, or their namespaces with %s, via -f.\n", exemptNamespacesPath)
}

// Uncapped: the operator reviews the whole set.
func reportExemptedImages(w io.Writer, exempt nriimagepolicy.ExemptRepositories, images []runningImage) {
	for _, namespace := range slices.Sorted(maps.Keys(exempt)) {
		fmt.Fprintf(w, "+ image policy: %s admitted by image repository:\n", namespace)
		for _, prefix := range exempt[namespace] {
			fmt.Fprintf(w, "    %s\n", prefix)
		}
	}
	if len(images) == 0 {
		return
	}
	fmt.Fprintf(w, "  The %d image(s) the cluster runs under those prefixes:\n", len(images))
	for _, image := range images {
		fmt.Fprintf(w, "    %s\n", image.line())
	}
	fmt.Fprintf(w, "  To pin them by digest instead, admit them with\n"+
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
