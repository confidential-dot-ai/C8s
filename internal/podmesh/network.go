package podmesh

import (
	"fmt"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
)

const GuestBridge = "c8spod0"

var GuestPodAddress = netip.MustParseAddr("10.255.254.2")

// ParseMeshPeers accepts exact IPv4 endpoints, never a subnet or local service.
func ParseMeshPeers(values []string) ([]netip.AddrPort, error) {
	peers := make([]netip.AddrPort, 0, len(values))
	local := netip.MustParsePrefix("10.255.254.0/30")
	for _, value := range values {
		peer, err := netip.ParseAddrPort(value)
		if err != nil {
			return nil, fmt.Errorf("mesh peer %q: %w", value, err)
		}
		addr := peer.Addr()
		if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || local.Contains(addr) || peer.Port() == 0 {
			return nil, fmt.Errorf("mesh peer %q must name a remote unicast IPv4 address and nonzero port", value)
		}
		peers = append(peers, peer)
	}
	slices.SortFunc(peers, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return slices.Compact(peers), nil
}

// IngressPorts returns only declared TCP ports of workload containers and native
// sidecars. Completed init containers never provide an ingress service.
func IngressPorts(pod *corev1.Pod) ([]uint16, error) {
	containers := slices.Clone(pod.Spec.Containers)
	for _, c := range pod.Spec.InitContainers {
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			containers = append(containers, c)
		}
	}
	var ports []uint16
	for _, c := range containers {
		for _, p := range c.Ports {
			if p.ContainerPort <= 0 || p.ContainerPort > 65535 {
				return nil, fmt.Errorf("container %q has invalid port %d", c.Name, p.ContainerPort)
			}
			if p.Protocol != "" && p.Protocol != corev1.ProtocolTCP {
				continue
			}
			if p.ContainerPort == 8443 || isMeshPort(p.ContainerPort) {
				return nil, fmt.Errorf("container %q port %d is reserved for the platform", c.Name, p.ContainerPort)
			}
			ports = append(ports, uint16(p.ContainerPort))
		}
	}
	slices.Sort(ports)
	return slices.Compact(ports), nil
}
