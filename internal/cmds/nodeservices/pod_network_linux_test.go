//go:build linux

package nodeservices

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func defaultRoute() netlink.Route {
	return netlink.Route{Family: netlink.FAMILY_V4, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, LinkIndex: 7, Priority: 100}
}

func TestPodDefaultRouteSelection(t *testing.T) {
	base := defaultRoute()
	higher := base
	higher.LinkIndex, higher.Priority = 8, 200
	specific := base
	specific.Dst = &net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)}
	ipv6 := base
	ipv6.Family = netlink.FAMILY_V6
	otherTable := base
	otherTable.Table = 100
	for _, routes := range [][]netlink.Route{{higher, base}, {specific, ipv6, otherTable, base}} {
		got, err := podDefaultRoute(routes)
		if err != nil || !reflect.DeepEqual(got, base) {
			t.Fatalf("selected %+v, %v; want %+v", got, err, base)
		}
	}
	base.Dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	if _, err := podDefaultRoute([]netlink.Route{base}); err != nil {
		t.Fatalf("explicit IPv4 default prefix rejected: %v", err)
	}
}

func TestPodDefaultRouteRejectsAmbiguityAndUnusableWinners(t *testing.T) {
	for _, routes := range [][]netlink.Route{nil, {defaultRoute(), defaultRoute()}} {
		if _, err := podDefaultRoute(routes); err == nil {
			t.Fatalf("accepted missing or ambiguous route: %+v", routes)
		}
	}
	for _, change := range []func(*netlink.Route){
		func(r *netlink.Route) { r.Family = netlink.FAMILY_V6 },
		func(r *netlink.Route) { r.Priority = -1 },
		func(r *netlink.Route) { r.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 7}} },
	} {
		route := defaultRoute()
		change(&route)
		if _, err := podDefaultRoute([]netlink.Route{route}); err == nil {
			t.Fatalf("accepted unsupported route: %+v", route)
		}
	}
	blocked, fallback := defaultRoute(), defaultRoute()
	blocked.Type, fallback.Priority = unix.RTN_BLACKHOLE, 200
	if _, err := podDefaultRoute([]netlink.Route{blocked, fallback}); err == nil {
		t.Fatal("ignored a winning blackhole route")
	}
}

func TestPodMTUFromNetwork(t *testing.T) {
	up := func(index, mtu int) netlink.Link {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: index, Flags: net.FlagUp, MTU: mtu}}
	}
	for _, tc := range []struct {
		name      string
		routeMTU  int
		ambiguous bool
		routesErr error
		link      netlink.Link
		linkErr   error
		want      int
	}{
		{name: "uplink1400", link: up(7, 1400), want: 1400},
		{name: "route cap", routeMTU: 1400, link: up(7, 1500), want: 1400},
		{name: "jumbo ceiling", link: up(7, 9000), want: 1500},
		{name: "invalid link", link: up(7, 0)},
		{name: "invalid route cap", routeMTU: 67, link: up(7, 1500)},
		{name: "ambiguous default", ambiguous: true, link: up(7, 1400)},
		{name: "route lookup failed", routesErr: errors.New("route lookup failed"), link: up(7, 1400)},
		{name: "link disappeared", linkErr: errors.New("link disappeared")},
		{name: "missing link"},
		{name: "link down", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 7, MTU: 1400}}},
		{name: "loopback", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 7, Flags: net.FlagUp | net.FlagLoopback, MTU: 1400}}},
		{name: "replaced link", link: up(8, 1400)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := defaultRoute()
			route.MTU = tc.routeMTU
			routes := []netlink.Route{route}
			if tc.ambiguous {
				routes = append(routes, route)
			}
			got, err := podMTUFromNetwork(func() ([]netlink.Route, error) { return routes, tc.routesErr }, func(index int) (netlink.Link, error) {
				if tc.routesErr != nil || tc.ambiguous {
					t.Fatal("read a link without a usable default route")
				}
				if index != route.LinkIndex {
					t.Fatalf("read unrelated interface %d", index)
				}
				return tc.link, tc.linkErr
			})
			if got != tc.want || (err == nil) != (tc.want != 0) {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}
