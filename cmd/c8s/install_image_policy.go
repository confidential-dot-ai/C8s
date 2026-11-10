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
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// policyModeFailClosed is the image-policy mode that denies. In `audit` the
// plugin logs the would-be denial and creates the container anyway.
const policyModeFailClosed = "fail-closed"

const uncoveredImagesListed = 20

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

func preflightImagePolicy(
	w io.Writer,
	values map[string]any,
	components []c8sComponent,
	servedDigests map[string]bool,
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
	admitted := availableImageDigests(values, components, servedDigests)
	reportExemptedImages(w, exempt, exemptNamespaceImages(pods, exempt))
	reportUnresolvedImages(w, unresolvedImages(pods, releaseNamespace, exempt))
	reportUncoveredWorkloads(w, uncoveredWorkloadImages(pods, releaseNamespace, exempt, admitted))

	uncovered := uncoveredPlatformImages(pods, releaseNamespace, exempt, admitted)
	if len(uncovered) == 0 {
		return "", nil
	}
	if force {
		return "installing with " + platformImageSummary(uncovered) + " outside the available image policy; those containers may fail to restart", nil
	}
	return "", fmt.Errorf("cannot confirm coverage for %s in the available image policy; registering the plugin restarts containerd, and these containers may fail to restart:\n  %s\nAdmit a provider namespace by listing it in %s with its image repositories in %s, admit a digest with nriImagePolicy.bootstrapAllowlist.workloads entries under any command and args, or re-run with --force to install anyway",
		platformImageSummary(uncovered), strings.Join(uncovered, "\n  "), exemptNamespacesPath, exemptRepositoriesPath)
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

func platformImageSummary(images []string) string {
	if len(images) == 1 {
		return "1 platform image"
	}
	return fmt.Sprintf("%d platform images", len(images))
}

type podImage struct {
	namespace        string
	pod              string
	container        string
	requested        string
	reference        string
	digest           string
	unresolvedReason string
}

func (i podImage) line() string {
	if i.digest == "" {
		return fmt.Sprintf("%s/%s (%s)  %s [%s]", i.namespace, i.pod, i.container, i.requested, i.unresolvedReason)
	}
	return fmt.Sprintf("%s/%s  %s", i.namespace, i.pod, i.reference)
}

func requestedPodImages(pod corev1.Pod) []podImage {
	var images []podImage
	appendImage := func(name, requested string, statuses []corev1.ContainerStatus) {
		status := containerStatusNamed(statuses, name)
		digest, unresolvedReason := resolveContainerImage(requested, status)
		images = append(images, podImage{
			namespace:        pod.Namespace,
			pod:              pod.Name,
			container:        name,
			requested:        requested,
			reference:        imageReference(requested, digest),
			digest:           digest,
			unresolvedReason: unresolvedReason,
		})
	}
	for _, c := range pod.Spec.InitContainers {
		appendImage(c.Name, c.Image, pod.Status.InitContainerStatuses)
	}
	for _, c := range pod.Spec.Containers {
		appendImage(c.Name, c.Image, pod.Status.ContainerStatuses)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		appendImage(c.Name, c.Image, pod.Status.EphemeralContainerStatuses)
	}
	return images
}

func containerStatusNamed(statuses []corev1.ContainerStatus, name string) corev1.ContainerStatus {
	for _, status := range statuses {
		if status.Name == name {
			return status
		}
	}
	return corev1.ContainerStatus{}
}

func collectPodImages(pods []corev1.Pod, accept func(corev1.Pod, podImage) bool) []podImage {
	var images []podImage
	for _, pod := range pods {
		if isTerminalPod(pod) {
			continue
		}
		for _, image := range requestedPodImages(pod) {
			if accept(pod, image) {
				images = append(images, image)
			}
		}
	}
	slices.SortFunc(images, func(a, b podImage) int { return strings.Compare(a.line(), b.line()) })
	seen := map[string]bool{}
	unique := images[:0]
	for _, image := range images {
		key := image.inventoryKey()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, image)
		}
	}
	return unique
}

func (i podImage) inventoryKey() string {
	if i.digest == "" {
		return i.line()
	}
	return i.namespace + "/" + i.reference
}

func resolveContainerImage(requested string, status corev1.ContainerStatus) (digest, unresolvedReason string) {
	requestedDigest := imageDigest(requested)
	observedDigest := imageDigest(status.ImageID, status.Image)
	if requestedDigest != "" && observedDigest != "" && requestedDigest != observedDigest {
		return "", "request and status digests differ"
	}
	if requestedDigest != "" {
		return requestedDigest, ""
	}
	if status.Image != "" && !imageStatusMatchesRequest(requested, status.Image) {
		return "", "request and status references differ"
	}
	if status.Image != "" && observedDigest != "" {
		return observedDigest, ""
	}
	return "", "digest unavailable in pod spec or status"
}

func imageStatusMatchesRequest(requested, observed string) bool {
	request, requestErr := reference.ParseDockerRef(requested)
	status, statusErr := reference.ParseDockerRef(observed)
	if requestErr != nil || statusErr != nil || request.Name() != status.Name() {
		return false
	}
	requestTag, requestTagged := request.(reference.Tagged)
	statusTag, statusTagged := status.(reference.Tagged)
	return requestTagged && statusTagged && requestTag.Tag() == statusTag.Tag()
}

func imageLines(images []podImage) []string {
	lines := make([]string, 0, len(images))
	for _, image := range images {
		lines = append(lines, image.line())
	}
	return lines
}

func isTerminalPod(p corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

func uncoveredImage(
	image podImage,
	releaseNamespace string,
	exempt nriimagepolicy.ExemptRepositories,
	admitted map[string]bool,
) bool {
	return image.digest != "" && image.namespace != releaseNamespace &&
		!exempt.Admits(image.namespace, image.requested) &&
		!admitted[image.digest]
}

func uncoveredPlatformImages(
	pods []corev1.Pod,
	releaseNamespace string,
	exempt nriimagepolicy.ExemptRepositories,
	admitted map[string]bool,
) []string {
	return cappedImageLines(collectPodImages(pods, func(pod corev1.Pod, image podImage) bool {
		return platformPod(pod) && uncoveredImage(image, releaseNamespace, exempt, admitted)
	}))
}

func uncoveredWorkloadImages(
	pods []corev1.Pod,
	releaseNamespace string,
	exempt nriimagepolicy.ExemptRepositories,
	admitted map[string]bool,
) []string {
	return cappedImageLines(collectPodImages(pods, func(pod corev1.Pod, image podImage) bool {
		return !platformPod(pod) && uncoveredImage(image, releaseNamespace, exempt, admitted)
	}))
}

func unresolvedImages(pods []corev1.Pod, releaseNamespace string, exempt nriimagepolicy.ExemptRepositories) []string {
	return cappedImageLines(collectPodImages(pods, func(pod corev1.Pod, image podImage) bool {
		return image.digest == "" && image.namespace != releaseNamespace && !exempt.Admits(image.namespace, image.requested)
	}))
}

func cappedImageLines(images []podImage) []string {
	lines := imageLines(images)
	if len(lines) > uncoveredImagesListed {
		rest := len(lines) - uncoveredImagesListed
		lines = append(lines[:uncoveredImagesListed:uncoveredImagesListed], fmt.Sprintf("… and %d more", rest))
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
func exemptNamespaceImages(pods []corev1.Pod, exempt nriimagepolicy.ExemptRepositories) []podImage {
	return collectPodImages(pods, func(pod corev1.Pod, image podImage) bool {
		return exempt.Admits(pod.Namespace, image.requested)
	})
}

func reportUnresolvedImages(w io.Writer, images []string) {
	if len(images) != 0 {
		fmt.Fprintf(w, "+ image policy: cannot resolve a current digest for these requested containers;\n"+
			"  their image coverage is unknown:\n    %s\n", strings.Join(images, "\n    "))
	}
}

func reportUncoveredWorkloads(w io.Writer, images []string) {
	if len(images) == 0 {
		return
	}
	fmt.Fprint(w, "+ image policy: these workload images are outside the available image policy;\n"+
		"  their containers may fail to restart:\n")
	for _, image := range images {
		fmt.Fprintf(w, "    %s\n", image)
	}
	fmt.Fprintf(w, "  Admit their digests with nriImagePolicy.bootstrapAllowlist.workloads entries\n"+
		"  under any command and args, or their namespaces with %s, via -f.\n", exemptNamespacesPath)
}

// Uncapped: the operator reviews the whole set.
func reportExemptedImages(w io.Writer, exempt nriimagepolicy.ExemptRepositories, images []podImage) {
	for _, namespace := range slices.Sorted(maps.Keys(exempt)) {
		fmt.Fprintf(w, "+ image policy: %s admitted by image repository:\n", namespace)
		for _, prefix := range exempt[namespace] {
			fmt.Fprintf(w, "    %s\n", prefix)
		}
	}
	if len(images) == 0 {
		return
	}
	fmt.Fprintf(w, "  The %d image(s) requested under those prefixes:\n", len(images))
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
		if types.IsCanonicalDigest(ref) {
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

func imageReference(requested, digest string) string {
	if digest == "" {
		return requested
	}
	if isBareDigest(requested) {
		return digest
	}
	named, err := reference.ParseDockerRef(requested)
	if err != nil {
		return digest
	}
	return reference.TrimNamed(named).String() + "@" + digest
}

func isBareDigest(ref string) bool {
	return strings.HasPrefix(ref, "sha256:")
}

func availableImageDigests(
	values map[string]any,
	components []c8sComponent,
	servedDigests map[string]bool,
) map[string]bool {
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
	maps.Copy(admitted, servedDigests)
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
