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
	for _, routes := range [][]netlink.Route{{higher, base}, {base, higher}, {specific, ipv6, otherTable, base}, {higher, higher, base}} {
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
		func(r *netlink.Route) { r.Table = 100 },
		func(r *netlink.Route) { r.Type = unix.RTN_BLACKHOLE },
		func(r *netlink.Route) { r.LinkIndex = 0 },
		func(r *netlink.Route) { r.Priority = -1 },
		func(r *netlink.Route) { r.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 7}} },
		func(r *netlink.Route) { r.Tos = 4 },
		func(r *netlink.Route) { r.Flags = unix.RTNH_F_DEAD },
		func(r *netlink.Route) { r.Flags = unix.RTNH_F_LINKDOWN },
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

func TestPreparePodFromNetlinkFixtures(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		linkMTU, routeMTU, want int
		ambiguous               bool
	}{
		{name: "uplink1400", linkMTU: 1400, want: 1400},
		{name: "route cap", linkMTU: 1500, routeMTU: 1400, want: 1400},
		{name: "jumbo ceiling", linkMTU: 9000, want: 1500},
		{name: "invalid link", linkMTU: 0},
		{name: "invalid route cap", linkMTU: 1500, routeMTU: 67},
		{name: "ambiguous default", linkMTU: 1400, ambiguous: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			route := defaultRoute()
			route.MTU = tc.routeMTU
			routes := []netlink.Route{route}
			if tc.ambiguous {
				routes = append(routes, route)
			}
			resolve := func() (int, error) {
				return podMTUFromNetwork(func() ([]netlink.Route, error) { return routes, nil }, func(index int) (netlink.Link, error) {
					if index != route.LinkIndex {
						t.Fatalf("read unrelated interface %d", index)
					}
					return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: index, Flags: net.FlagUp, MTU: tc.linkMTU}}, nil
				})
			}
			err := prepare(root, podDocument(t), resolve)
			if tc.want == 0 {
				if err == nil {
					t.Fatal("accepted invalid guest network")
				}
				assertNoPodOutputs(t, root)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertPreparedCNI(t, root, tc.want)
			}
		})
	}
}

func TestPodMTUReadFailuresAndInvalidLinks(t *testing.T) {
	routes := func() ([]netlink.Route, error) { return []netlink.Route{defaultRoute()}, nil }
	if _, err := podMTUFromNetwork(func() ([]netlink.Route, error) { return nil, errors.New("route lookup failed") }, func(int) (netlink.Link, error) {
		t.Fatal("read link after failed route lookup")
		return nil, nil
	}); err == nil {
		t.Fatal("ignored route lookup error")
	}
	for _, lookup := range []func(int) (netlink.Link, error){
		func(int) (netlink.Link, error) { return nil, errors.New("link disappeared") },
		func(int) (netlink.Link, error) { return nil, nil },
		func(int) (netlink.Link, error) {
			return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 7, MTU: 1400}}, nil
		},
		func(int) (netlink.Link, error) {
			return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 7, Flags: net.FlagUp | net.FlagLoopback, MTU: 1400}}, nil
		},
		func(int) (netlink.Link, error) {
			return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 8, Flags: net.FlagUp, MTU: 1400}}, nil
		},
	} {
		if _, err := podMTUFromNetwork(routes, lookup); err == nil {
			t.Fatal("accepted missing, down, loopback or replaced link")
		}
	}
}
