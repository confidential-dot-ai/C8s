package workloadclaims

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

// PodCIDRs is every range a node assigns pod addresses from.
func PodCIDRs(node *corev1.Node) []string {
	var ranges []string
	for _, cidr := range append([]string{node.Spec.PodCIDR}, node.Spec.PodCIDRs...) {
		if cidr != "" && !slices.Contains(ranges, cidr) {
			ranges = append(ranges, cidr)
		}
	}
	return ranges
}
