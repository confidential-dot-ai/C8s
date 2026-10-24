//go:build linux

package nodeservices

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func discoverPodMTU() (int, error) {
	return podMTUFromNetwork(func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	}, netlink.LinkByIndex)
}

// These lookups only read the guest namespace. Tests supply the same netlink
// objects without consulting or changing the host network.
func podMTUFromNetwork(routes func() ([]netlink.Route, error), link func(int) (netlink.Link, error)) (int, error) {
	all, err := routes()
	if err != nil {
		return 0, fmt.Errorf("read Pod uplink routes: %w", err)
	}
	route, err := podDefaultRoute(all)
	if err != nil {
		return 0, err
	}
	device, err := link(route.LinkIndex)
	if err != nil {
		return 0, fmt.Errorf("read Pod uplink link: %w", err)
	}
	if device == nil || device.Attrs() == nil {
		return 0, fmt.Errorf("pod uplink link is missing")
	}
	attrs := device.Attrs()
	if attrs.Index != route.LinkIndex || attrs.Flags&net.FlagUp == 0 || attrs.Flags&net.FlagLoopback != 0 {
		return 0, fmt.Errorf("pod uplink must be the selected, up, non-loopback interface")
	}
	return podNetworkMTU(attrs.MTU, route.MTU)
}

func podDefaultRoute(routes []netlink.Route) (netlink.Route, error) {
	var selected netlink.Route
	found, ambiguous := false, false
	for _, route := range routes {
		if route.Family != netlink.FAMILY_V4 || route.Table != unix.RT_TABLE_MAIN {
			continue
		}
		if route.Dst != nil {
			ones, bits := route.Dst.Mask.Size()
			if ones != 0 || bits != 32 || !route.Dst.IP.IsUnspecified() {
				continue
			}
		}
		if route.Priority < 0 {
			return netlink.Route{}, fmt.Errorf("invalid Pod default-route metric")
		}
		if !found || route.Priority < selected.Priority {
			selected, found, ambiguous = route, true, false
		} else if route.Priority == selected.Priority {
			ambiguous = true
		}
	}
	if !found || ambiguous {
		return netlink.Route{}, fmt.Errorf("pod network requires an unambiguous IPv4 main-table default route")
	}
	if selected.Type != unix.RTN_UNICAST || selected.LinkIndex <= 0 || len(selected.MultiPath) != 0 ||
		selected.Tos != 0 || selected.Flags&(unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) != 0 {
		return netlink.Route{}, fmt.Errorf("pod default route must be a live single-link unicast route")
	}
	return selected, nil
}
