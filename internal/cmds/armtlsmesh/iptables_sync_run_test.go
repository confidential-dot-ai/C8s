//go:build linux

package armtlsmesh

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// localIPv4 returns a non-loopback IPv4 address bound to a local interface,
// or skips the test if none exists (runIptablesSync verifies node-IP
// locality against real interfaces).
func localIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("net.InterfaceAddrs: %v", err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		return ip.String()
	}
	t.Skip("no non-loopback IPv4 interface address available")
	return ""
}

func defaultTestSyncConfig() *iptablesSyncConfig {
	return &iptablesSyncConfig{
		outboundPort:            15001,
		uid:                     defaultProxyUID,
		excludeUIDs:             "0",
		excludeSourceNamespaces: defaultMeshExcludedSourceNamespacesCSV(),
		resyncPeriod:            30 * time.Second,
		watchdogPeriod:          2 * time.Second,
		ipsetMaxElem:            defaultIPSetMaxElem,
		cwInboundPassthrough:    formatCWPassthrough(defaultCWPassthrough),
		logLevel:                "error",
	}
}

func TestRunIptablesSyncValidationErrors(t *testing.T) {
	t.Setenv("NODE_IP", "")
	tests := []struct {
		name    string
		mutate  func(*iptablesSyncConfig)
		env     string // NODE_IP value ("" = unset)
		wantErr string
	}{
		{"bad outbound port", func(c *iptablesSyncConfig) { c.outboundPort = 0 }, "", "out of range"},
		{"bad resync period", func(c *iptablesSyncConfig) { c.resyncPeriod = 0 }, "", "resync-period must be positive"},
		{"bad watchdog period", func(c *iptablesSyncConfig) { c.watchdogPeriod = -time.Second }, "", "watchdog-period must be positive"},
		{"bad ipset maxelem", func(c *iptablesSyncConfig) { c.ipsetMaxElem = 0 }, "", "ipset-maxelem must be positive"},
		{"missing node IP", func(c *iptablesSyncConfig) {}, "", "node IP required"},
		{"node IP from env invalid", func(c *iptablesSyncConfig) {}, "not-an-ip", "not a valid IP address"},
		{"node IP not local", func(c *iptablesSyncConfig) { c.nodeIPs = []string{"203.0.113.7"} }, "", "not bound to any local interface"},
		{"bad exclude uids", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.excludeUIDs = "root"
		}, "", "invalid exclude-uid"},
		{"bad cw passthrough", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.cwInboundPassthrough = "icmp:1"
		}, "", "invalid cw-inbound-passthrough protocol"},
		{"bad log level", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.logLevel = "shouty"
		}, "", "--log-level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NODE_IP", tt.env)
			cfg := defaultTestSyncConfig()
			tt.mutate(cfg)
			err := runIptablesSync(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runIptablesSync() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestStringSetAndNewMembers(t *testing.T) {
	prev := stringSet([]string{"a", "b"})
	curr := stringSet([]string{"b", "c", "d"})
	got := newMembers(prev, curr)
	if len(got) != 2 {
		t.Fatalf("newMembers = %v, want 2 elements", got)
	}
	seen := stringSet(got)
	if _, ok := seen["c"]; !ok {
		t.Errorf("missing c in %v", got)
	}
	if _, ok := seen["d"]; !ok {
		t.Errorf("missing d in %v", got)
	}
}

func TestPodIPSetMembersExceeds(t *testing.T) {
	m := podIPSetMembers{allIPv4: []string{"1.1.1.1", "2.2.2.2"}}
	if !m.exceeds(1) {
		t.Error("exceeds(1) = false, want true")
	}
	if m.exceeds(2) {
		t.Error("exceeds(2) = true, want false")
	}
	if (podIPSetMembers{cwIPv6: []string{"fd00::1", "fd00::2"}}).exceeds(1) != true {
		t.Error("cwIPv6 overflow not detected")
	}
}

func TestCanonicalNodeIPs(t *testing.T) {
	got := canonicalNodeIPs(map[iptablesFamily]string{
		iptablesFamilyIPv6: "fd00::1",
		iptablesFamilyIPv4: "10.0.0.1",
	})
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "fd00::1" {
		t.Errorf("canonicalNodeIPs = %v, want IPv4 first then IPv6", got)
	}
}

func TestDiscoverMissingFamilyNodeIPsNoMissing(t *testing.T) {
	// Both families explicitly provided -> the function must discover nothing.
	got, err := discoverMissingFamilyNodeIPs(map[iptablesFamily]string{
		iptablesFamilyIPv4: "10.0.0.1",
		iptablesFamilyIPv6: "fd00::1",
	})
	if err != nil {
		t.Fatalf("discover (no missing): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("both families present should discover nothing; got %v", got)
	}
}

func addr(t *testing.T, s string, ones int, bits int) ifaceAddr {
	ip := mustParseIP(t, s)
	return ifaceAddr{ip: ip, mask: net.CIDRMask(ones, bits)}
}

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}

// The selector must prefer a host-usable IPv6 on the interface that also
// carries the provided node IP (the egress interface) over a higher-prefix
// IPv6 on a non-primary/overlay interface.
func TestSelectMissingFamilyNodeIPsPrefersSameCarrier(t *testing.T) {
	byFamily := map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.5"}
	needed := map[iptablesFamily]bool{iptablesFamilyIPv6: true}
	sets := []ifaceAddrSet{
		{name: "eth0", addrs: []ifaceAddr{
			addr(t, "10.0.0.5", 24, 32),
			addr(t, "fd00::5", 64, 128), // host-style, on the same carrier
		}},
		{name: "cni0", addrs: []ifaceAddr{
			addr(t, "fd00::6", 128, 128), // higher prefix, but overlay interface
		}},
	}
	got, err := selectMissingFamilyNodeIPs(byFamily, needed, sets)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got[iptablesFamilyIPv6] != "fd00::5" {
		t.Errorf("selected IPv6 = %q, want fd00::5 (same-carrier interface)", got[iptablesFamilyIPv6])
	}
}

// When a host-usable address of the missing family exists only on a
// non-primary (overlay) interface and not on the egress interface, the
// selector must fail loudly rather than install a possibly-misrouted DNAT.
func TestSelectMissingFamilyNodeIPsErrorsOnOverlayOnly(t *testing.T) {
	byFamily := map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.5"}
	needed := map[iptablesFamily]bool{iptablesFamilyIPv6: true}
	sets := []ifaceAddrSet{
		{name: "eth0", addrs: []ifaceAddr{addr(t, "10.0.0.5", 24, 32)}},
		{name: "cni0", addrs: []ifaceAddr{addr(t, "fd00::6", 128, 128)}},
	}
	if _, err := selectMissingFamilyNodeIPs(byFamily, needed, sets); err == nil {
		t.Fatal("expected an error when the only host-usable IPv6 is on an overlay interface")
	}
}

// A network aggregate (prefix shorter than /64 with zero interface bits, e.g.
// a /56) is not a host address and must not be selected as a DNAT target.
func TestSelectMissingFamilyNodeIPsRejectsAggregate(t *testing.T) {
	byFamily := map[iptablesFamily]string{iptablesFamilyIPv4: "148.113.0.5"}
	needed := map[iptablesFamily]bool{iptablesFamilyIPv6: true}
	sets := []ifaceAddrSet{
		{name: "eth0", addrs: []ifaceAddr{
			addr(t, "148.113.0.5", 24, 32),
			addr(t, "2607:5300:21a:8c00::", 56, 128), // /56 network aggregate
		}},
	}
	got, err := selectMissingFamilyNodeIPs(byFamily, needed, sets)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if _, ok := got[iptablesFamilyIPv6]; ok {
		t.Errorf("selected aggregate IPv6 %q; expected no IPv6 entry", got[iptablesFamilyIPv6])
	}
}

// A link-local-only family presence is not a host address: the selector must
// skip it and report the family as genuinely absent (single-stack), not error.
func TestSelectMissingFamilyNodeIPsSkipsLinkLocal(t *testing.T) {
	byFamily := map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.5"}
	needed := map[iptablesFamily]bool{iptablesFamilyIPv6: true}
	sets := []ifaceAddrSet{
		{name: "eth0", addrs: []ifaceAddr{
			addr(t, "10.0.0.5", 24, 32),
			addr(t, "fe80::1", 64, 128),
		}},
	}
	got, err := selectMissingFamilyNodeIPs(byFamily, needed, sets)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if _, ok := got[iptablesFamilyIPv6]; ok {
		t.Errorf("selected link-local IPv6 %q; expected no IPv6 entry", got[iptablesFamilyIPv6])
	}
}

// The pure selector is exercised by injected groups; this smoke test still
// drives the real host enumeration to confirm discovery returns nothing
// without error on the CI container (whose v6 is a /56 aggregate).
func TestDiscoverMissingFamilyNodeIPsRealHostSmoke(t *testing.T) {
	v4 := localIPv4(t)
	got, err := discoverMissingFamilyNodeIPs(map[iptablesFamily]string{iptablesFamilyIPv4: v4})
	if err != nil {
		t.Fatalf("discover (v4 present on real host): %v", err)
	}
	if _, ok := got[iptablesFamilyIPv4]; ok {
		t.Errorf("discover returned IPv4 %q even though it was provided", got[iptablesFamilyIPv4])
	}
}
