package nodeservices

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// bakedResolvedConfDir holds the measured image's upstream resolvers as
	// systemd-resolved drop-ins.
	bakedResolvedConfDir = "/etc/systemd/resolved.conf.d"
	// podResolvConfPath is the resolver file the standalone kubelet hands the
	// pod (kubelet.yaml resolvConf).
	podResolvConfPath = PodDir + "/resolv.conf"
)

// podResolvConf renders the pod's resolver file from the measured drop-ins
// alone. The guest's own resolver list also carries whatever the host's
// address assignment supplied, which the pod must never be handed: the pod's
// name resolution is the host's to answer on the wire, not to redirect
// through a resolver the measured configuration does not name.
func podResolvConf(rootDir string) ([]byte, error) {
	dir := filepath.Join(rootDir, bakedResolvedConfDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read measured resolver configuration: %w", err)
	}
	var resolvers []netip.Addr
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read measured resolver configuration: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(key) != "DNS" {
				continue
			}
			for _, field := range strings.Fields(value) {
				// resolved accepts address#servername and address%interface.
				address, _, _ := strings.Cut(field, "#")
				address, _, _ = strings.Cut(address, "%")
				addr, err := netip.ParseAddr(address)
				if err != nil {
					return nil, fmt.Errorf("measured resolver %q: %w", field, err)
				}
				if !podResolverAddress(addr) {
					return nil, fmt.Errorf("measured resolver %s is not a remote unicast IPv4 address", addr)
				}
				if !slices.Contains(resolvers, addr) {
					resolvers = append(resolvers, addr)
				}
			}
		}
	}
	if len(resolvers) == 0 {
		return nil, errors.New("the measured image names no upstream resolver")
	}
	var out bytes.Buffer
	for _, addr := range resolvers {
		fmt.Fprintf(&out, "nameserver %s\n", addr)
	}
	return out.Bytes(), nil
}

// podResolverAddress is a resolver the pod can reach under its egress rules:
// remote unicast IPv4, so neither the guest, the pod's own link nor a
// link-local address.
func podResolverAddress(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !podGuestLink.Contains(addr)
}

var podGuestLink = netip.MustParsePrefix("10.255.254.0/30")
