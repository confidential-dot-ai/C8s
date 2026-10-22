//go:build linux

package ruleset

import (
	"errors"
	"net/netip"
	"testing"
)

// Trusted policy a ruleset cannot express exactly is refused, so no pod is
// protected by a ruleset wider than the policy it came from.
func TestPolicyRefusesWhatARuleCannotExpress(t *testing.T) {
	tests := []struct {
		name  string
		spoil func(*Policy)
	}{
		{"no resolver", func(p *Policy) { p.Resolver = netip.Addr{} }},
		{"wildcard resolver", func(p *Policy) { p.Resolver = netip.MustParseAddr("0.0.0.0") }},
		{
			"broadcast resolver",
			func(p *Policy) {
				p.Resolver = netip.MustParseAddr("255.255.255.255")
			},
		},
		{"multicast resolver", func(p *Policy) { p.Resolver = netip.MustParseAddr("224.0.0.251") }},
		{"loopback resolver", func(p *Policy) { p.Resolver = netip.MustParseAddr("127.0.0.53") }},
		{"IPv6 loopback resolver", func(p *Policy) { p.Resolver = netip.MustParseAddr("::1") }},
		{"link-local resolver", func(p *Policy) { p.Resolver = netip.MustParseAddr("169.254.0.53") }},
		{"IPv6 link-local resolver", func(p *Policy) { p.Resolver = netip.MustParseAddr("fe80::53") }},
		{"4-in-6 resolver", func(p *Policy) { p.Resolver = netip.MustParseAddr("::ffff:10.53.0.10") }},
		{"no outbound capture port", func(p *Policy) { p.Capture.Outbound = 0 }},
		{"no inbound capture port", func(p *Policy) { p.Capture.Inbound = 0 }},
		{"no health port", func(p *Policy) { p.Capture.Health = 0 }},
		{"colliding capture ports", func(p *Policy) { p.Capture.Inbound = p.Capture.Outbound }},
		{"root mesh UID", func(p *Policy) { p.MeshUID = 0 }},
		{"root role UID", func(p *Policy) { p.Roles[0].UID = 0 }},
		{"role UID is the mesh UID", func(p *Policy) { p.Roles[0].UID = p.MeshUID }},
		{"role UID reused", func(p *Policy) {
			p.Roles = append(p.Roles, Role{
				UID:          p.Roles[0].UID,
				Destinations: p.Roles[0].Destinations,
			})
		}},
		{"role reaching nothing", func(p *Policy) { p.Roles[0].Destinations = nil }},
		{"destination without port", func(p *Policy) { p.Roles[0].Destinations[0].Port = 0 }},
		{"destination without address", func(p *Policy) { p.Roles[0].Destinations[0].Addr = netip.Addr{} }},
		{
			"broadcast destination",
			func(p *Policy) {
				p.Roles[0].Destinations[0].Addr = netip.MustParseAddr("255.255.255.255")
			},
		},
		{"pod-local destination", func(p *Policy) { p.Roles[0].Destinations[0].Addr = netip.MustParseAddr("127.0.0.1") }},
		{"exit without port", func(p *Policy) { p.Exits[0].Port = 0 }},
		{"unset exit range", func(p *Policy) { p.Exits[0].Range = netip.Prefix{} }},
		{"exit range carrying host bits", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("10.43.0.2/24") }},
		{"exit to every address", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("0.0.0.0/0") }},
		{"exit to every IPv6 address", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("::/0") }},
		{"exit over loopback", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("96.0.0.0/3") }},
		{"exit to link-local", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("169.254.169.254/32") }},
		{"exit to multicast", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("239.0.0.0/8") }},
		{"exit to broadcast", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("255.255.255.255/32") }},
		{"exit to IPv6 link-local", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("fe80::/64") }},
		{"4-in-6 exit", func(p *Policy) { p.Exits[0].Range = netip.MustParsePrefix("::ffff:10.43.0.2/128") }},
		{"server egress port with no cluster ranges to exclude", func(p *Policy) {
			p.Server = serverPolicy().Server
			p.Server.ClusterRanges = nil
		}},
		{"cluster range carrying host bits", func(p *Policy) {
			p.Server = serverPolicy().Server
			p.Server.ClusterRanges[0] = netip.PrefixFrom(netip.MustParseAddr("10.52.0.1"), 16)
		}},
		{"unset cluster range", func(p *Policy) {
			p.Server = serverPolicy().Server
			p.Server.ClusterRanges[0] = netip.Prefix{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			test.spoil(&policy)
			if err := policy.validate(); !errors.Is(err, ErrPolicy) {
				t.Fatalf("error = %v, want ErrPolicy", err)
			}
		})
	}
}

func TestPolicyAcceptsANodesTrustedInput(t *testing.T) {
	for name, policy := range map[string]Policy{"member": testPolicy(), "server": serverPolicy()} {
		t.Run(name, func(t *testing.T) {
			if err := policy.validate(); err != nil {
				t.Fatalf("validate = %v", err)
			}
		})
	}
}
