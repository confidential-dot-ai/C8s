//go:build linux

package armtlsmesh

import (
	"fmt"
	"net"
	"slices"

	"github.com/vishvananda/netlink"
)

// defaultLocalRouteCheck asks the kernel — via rtnetlink RTM_GETROUTE — which
// interface a destination IP would actually leave through, and reports
// whether that interface is in the caller's allow-list. The kernel performs
// the longest-prefix and metric tiebreak so we don't reimplement routing
// here. Read-only netlink works under default seccomp without NET_ADMIN.
func defaultLocalRouteCheck(destIP string, allowedIfaces []string) (bool, error) {
	if len(allowedIfaces) == 0 {
		return false, nil
	}
	parsed := net.ParseIP(destIP)
	if parsed == nil {
		return false, nil
	}
	routes, err := netlink.RouteGet(parsed)
	if err != nil {
		return false, fmt.Errorf("netlink route get %s: %w", destIP, err)
	}
	if len(routes) == 0 {
		return false, nil
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return false, fmt.Errorf("netlink link by index %d: %w", routes[0].LinkIndex, err)
	}
	return ifaceAllowed(link.Attrs().Name, allowedIfaces), nil
}

func ifaceAllowed(iface string, allowedIfaces []string) bool {
	return slices.Contains(allowedIfaces, iface)
}
