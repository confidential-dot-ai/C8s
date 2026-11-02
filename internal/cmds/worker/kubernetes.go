package worker

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// reservedRanges are the IPv4 blocks no pod or Service range may reach into:
// this network (so no default route), loopback, link-local and multicast.
var reservedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
}

func (k Kubernetes) validate(nodeSubnets []netip.Prefix) error {
	if err := checkAPIServer(k.APIServer); err != nil {
		return fmt.Errorf("kubernetes.apiServer %w", err)
	}
	if _, err := caCertificate(k.CACertificate); err != nil {
		return fmt.Errorf("kubernetes.caCertificate %w", err)
	}
	pods, err := clusterRange(k.PodCIDR)
	if err != nil {
		return fmt.Errorf("kubernetes.podCIDR %w", err)
	}
	services, err := clusterRange(k.ServiceCIDR)
	if err != nil {
		return fmt.Errorf("kubernetes.serviceCIDR %w", err)
	}
	if !holdsHostAddresses(services) {
		return fmt.Errorf("kubernetes.serviceCIDR %s must be a /30 or wider", services)
	}
	if pods.Overlaps(services) {
		return fmt.Errorf("kubernetes.podCIDR %s overlaps kubernetes.serviceCIDR %s", pods, services)
	}
	if subnet, inCluster, ok := firstOverlap(nodeSubnets, pods, services); ok {
		return fmt.Errorf("kubernetes: the pinned CDS configuration's node subnet %s overlaps the cluster range %s", subnet, inCluster)
	}
	if err := checkClusterDNS(k.ClusterDNS, services); err != nil {
		return fmt.Errorf("kubernetes.clusterDNS %w", err)
	}
	return nil
}

// checkAPIServer accepts a bare <host>:<port>: the host a lowercase DNS name
// or a unicast IPv4 address, the port a canonical 1..65535.
func checkAPIServer(address string) error {
	switch {
	case strings.Contains(address, "://"):
		return fmt.Errorf("%q must not carry a scheme", address)
	case strings.Contains(address, "/"):
		return fmt.Errorf("%q must not carry a path", address)
	case strings.Contains(address, "@"):
		return fmt.Errorf("%q must not carry userinfo", address)
	case strings.ContainsAny(address, "[]"):
		return fmt.Errorf("%q must not bracket its host", address)
	}
	host, port, ok := strings.Cut(address, ":")
	if !ok {
		return fmt.Errorf("%q must be <host>:<port>", address)
	}
	if !isCanonicalPort(port) {
		return fmt.Errorf("%q must name a port 1..65535 without leading zeros", address)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := launchconfig.ValidateRoutableIPv4(addr); err != nil {
			return fmt.Errorf("%q host %w", address, err)
		}
		return nil
	}
	if err := launchconfig.ValidateHostname(host); err != nil {
		return fmt.Errorf("%q host %w", address, err)
	}
	return nil
}

func isCanonicalPort(text string) bool {
	port, err := strconv.ParseUint(text, 10, 16)
	return err == nil && port >= 1 && !strings.HasPrefix(text, "0")
}

// caCertificate accepts one PEM CERTIFICATE block holding a CA certificate,
// followed by nothing but whitespace.
func caCertificate(text string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(text))
	switch {
	case block == nil:
		return nil, errors.New("must hold a PEM block")
	case block.Type != "CERTIFICATE":
		return nil, fmt.Errorf("must be a PEM CERTIFICATE block, not %s", block.Type)
	case len(block.Headers) != 0:
		return nil, errors.New("must carry no PEM headers")
	case strings.TrimSpace(string(rest)) != "":
		return nil, errors.New("must hold exactly one PEM block and nothing after it")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("must hold an X.509 certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("must be a CA certificate")
	}
	return cert, nil
}

// clusterRange parses a pod or Service range: an IPv4 range named by its
// network address that reaches into no reserved block.
func clusterRange(text string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil || !isIPv4Range(prefix) {
		return netip.Prefix{}, fmt.Errorf("%q must be an IPv4 range such as 10.52.0.0/16", text)
	}
	if hasHostBits(prefix) {
		return netip.Prefix{}, fmt.Errorf("%q must be named by its network address, %s", text, prefix.Masked())
	}
	for _, reserved := range reservedRanges {
		if prefix.Overlaps(reserved) {
			return netip.Prefix{}, fmt.Errorf("%s reaches into the reserved range %s", prefix, reserved)
		}
	}
	return prefix, nil
}

func isIPv4Range(prefix netip.Prefix) bool {
	return prefix.Addr().Is4()
}

func hasHostBits(prefix netip.Prefix) bool {
	return prefix != prefix.Masked()
}

// holdsHostAddresses reports whether an IPv4 range has an address besides its
// network and broadcast addresses.
func holdsHostAddresses(prefix netip.Prefix) bool {
	return prefix.Bits() <= 30
}

// firstOverlap is the first subnet overlapping one of ranges, and that range.
func firstOverlap(subnets []netip.Prefix, ranges ...netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	for _, subnet := range subnets {
		for _, r := range ranges {
			if subnet.Overlaps(r) {
				return subnet, r, true
			}
		}
	}
	return netip.Prefix{}, netip.Prefix{}, false
}

func checkClusterDNS(text string, services netip.Prefix) error {
	addr, err := netip.ParseAddr(text)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("%q must be an IPv4 address", text)
	}
	if !services.Contains(addr) {
		return fmt.Errorf("%s must be inside kubernetes.serviceCIDR %s", addr, services)
	}
	if isNetworkAddress(services, addr) || isBroadcastAddress(services, addr) {
		return fmt.Errorf("%s must be neither the network nor the broadcast address of kubernetes.serviceCIDR %s", addr, services)
	}
	return nil
}

func isNetworkAddress(prefix netip.Prefix, addr netip.Addr) bool {
	return addr == prefix.Masked().Addr()
}

// isBroadcastAddress reports whether addr is the last address of the IPv4
// range.
func isBroadcastAddress(prefix netip.Prefix, addr netip.Addr) bool {
	return prefix.Contains(addr) && !prefix.Contains(addr.Next())
}
