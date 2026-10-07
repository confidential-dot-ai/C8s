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
		{"no resolver", func(p *Policy) { p.Resolvers = nil }},
		{"wildcard resolver", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("0.0.0.0") }},
		{"multicast resolver", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("224.0.0.251") }},
		{"loopback resolver", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("127.0.0.53") }},
		{"IPv6 loopback resolver", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("::1") }},
		{"link-local resolver", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("169.254.0.53") }},
		{"IPv6 link-local resolver", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("fe80::53") }},
		{"4-in-6 resolver", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("::ffff:10.53.0.10") }},
		{"unset resolver", func(p *Policy) { p.Resolvers[0] = netip.Addr{} }},
		{"no outbound capture port", func(p *Policy) { p.Capture.Outbound = 0 }},
		{"no inbound capture port", func(p *Policy) { p.Capture.Inbound = 0 }},
		{"no health port", func(p *Policy) { p.Capture.Health = 0 }},
		{"colliding capture ports", func(p *Policy) { p.Capture.Inbound = p.Capture.Outbound }},
		{"root mesh UID", func(p *Policy) { p.MeshUID = 0 }},
		{"root role UID", func(p *Policy) { p.Roles[0].UID = 0 }},
		{"role UID is the mesh UID", func(p *Policy) { p.Roles[0].UID = p.MeshUID }},
		{"role UID reused", func(p *Policy) {
			p.Roles = append(p.Roles, Role{UID: p.Roles[0].UID, Destinations: p.Roles[0].Destinations})
		}},
		{"role reaching nothing", func(p *Policy) { p.Roles[0].Destinations = nil }},
		{"destination without port", func(p *Policy) { p.Roles[0].Destinations[0].Port = 0 }},
		{"destination without address", func(p *Policy) { p.Roles[0].Destinations[0].Addr = netip.Addr{} }},
		{"pod-local destination", func(p *Policy) { p.Roles[0].Destinations[0].Addr = netip.MustParseAddr("127.0.0.1") }},
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
	if err := testPolicy().validate(); err != nil {
		t.Fatalf("validate = %v", err)
	}
}
