package workloadclaims

import (
	"net"
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

// NodeHostCIDRs derives the inventory dial bound from node objects: one host
// route per InternalIP. A host route per node rather than a covering range,
// deliberately — on a CNI that assigns pod IPs from the node subnet (AWS VPC
// CNI, Azure CNI) every range covering the nodes covers the pods too, and the
// bound would look configured and be absent. A node address inside a pod
// range is excluded and reported instead: node and pod addresses are not
// separable there. Where the CNI owns IPAM and leaves podCIDR empty, that
// check simply does not run. The c8s CLI preflights the same derivation at
// install time.
func NodeHostCIDRs(nodes []*corev1.Node) (hosts []*net.IPNet, excluded []string) {
	var podRanges []*net.IPNet
	for _, n := range nodes {
		for _, c := range PodCIDRs(n) {
			if _, network, err := net.ParseCIDR(c); err == nil {
				podRanges = append(podRanges, network)
			}
		}
	}

	seen := map[string]bool{}
	for _, n := range nodes {
		for _, a := range n.Status.Addresses {
			if a.Type != corev1.NodeInternalIP {
				continue
			}
			ip := net.ParseIP(a.Address)
			if ip == nil || !ip.IsGlobalUnicast() {
				continue
			}
			inPodRange := false
			for _, r := range podRanges {
				if r.Contains(ip) {
					excluded = append(excluded, n.Name+"/"+a.Address)
					inPodRange = true
					break
				}
			}
			if inPodRange {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr := &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
			if !seen[cidr.String()] {
				seen[cidr.String()] = true
				hosts = append(hosts, cidr)
			}
		}
	}
	return hosts, excluded
}
