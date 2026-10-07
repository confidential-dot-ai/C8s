//go:build linux

package armtlsmesh

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

var defaultMeshExcludedSourceNamespaces = []string{
	"kube-system",
}

func defaultMeshExcludedSourceNamespacesCSV() string {
	return strings.Join(defaultMeshExcludedSourceNamespaces, ",")
}

func parseExcludedNamespaces(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for part := range strings.SplitSeq(raw, ",") {
		ns := strings.TrimSpace(part)
		if ns == "" {
			continue
		}
		out[ns] = struct{}{}
	}
	return out
}

// labelConfidentialWorkload is the pod label the injection webhook mirrors
// from the confidential.ai/cw annotation. Must equal webhook.LabelWorkload;
// a unit test asserts the two stay in sync so this package needs no runtime
// dependency on the webhook package.
const labelConfidentialWorkload = "confidential.ai/cw"

func podIsConfidentialWorkload(pod *corev1.Pod) bool {
	return pod.Labels[labelConfidentialWorkload] != ""
}

func podEligibleForMeshEndpoint(pod *corev1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed
}

func podEligibleForMeshSource(pod *corev1.Pod, excludedNamespaces map[string]struct{}) bool {
	if !podEligibleForMeshEndpoint(pod) {
		return false
	}
	_, excluded := excludedNamespaces[pod.Namespace]
	return !excluded
}
