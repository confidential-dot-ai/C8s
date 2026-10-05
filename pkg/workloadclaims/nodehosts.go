package workloadclaims

import (
	"net"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
)

// cidrSet is the membership check behind CIDRHosts and NodeHosts.
type cidrSet []*net.IPNet

func (s cidrSet) contains(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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
		for _, c := range append([]string{n.Spec.PodCIDR}, n.Spec.PodCIDRs...) {
			if c == "" {
				continue
			}
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

// NodeHosts is an InventoryHosts derived from the cluster's node objects and
// swapped atomically by the caller's informer. Before the first SetNodes it
// holds nothing, so Contains fails closed.
type NodeHosts struct {
	snap atomic.Pointer[cidrSet]
}

// SetNodes re-derives the bound and swaps it in. It reports the node
// addresses excluded for sitting inside a pod range, so the caller can log
// them per change rather than per lookup.
func (h *NodeHosts) SetNodes(nodes []*corev1.Node) (excluded []string) {
	hosts, excluded := NodeHostCIDRs(nodes)
	set := cidrSet(hosts)
	h.snap.Store(&set)
	return excluded
}

func (h *NodeHosts) Contains(host string) bool {
	snap := h.snap.Load()
	return snap != nil && snap.contains(host)
}

// Hosts lists the node addresses in the bound.
func (h *NodeHosts) Hosts() []string {
	snap := h.snap.Load()
	if snap == nil {
		return nil
	}
	hosts := make([]string, 0, len(*snap))
	for _, n := range *snap {
		hosts = append(hosts, n.IP.String())
	}
	return hosts
}

func (h *NodeHosts) Empty() bool {
	snap := h.snap.Load()
	return snap == nil || len(*snap) == 0
}
