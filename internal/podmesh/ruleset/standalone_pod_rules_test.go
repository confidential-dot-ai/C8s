//go:build linux

package ruleset

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func standalonePolicy() Policy {
	p := testPolicy()
	p.Roles, p.ClusterRanges = nil, nil
	p.Pod = &PodPolicy{Peers: []Destination{
		{netip.MustParseAddr("203.0.113.7"), 8080},
		{netip.MustParseAddr("198.51.100.9"), 443},
	}}
	return p
}

func ruleNames(c chain) []string {
	names := make([]string, 0, len(c.rules))
	for _, r := range c.rules {
		names = append(names, r.name)
	}
	return names
}

// A standalone Pod captures only its signed peer tuples, admits ordinary
// IPv4 TCP/UDP egress after denying link-local, and holds none of a member
// pod's per-identity or resolver rules.
func TestStandalonePodRulesCaptureOnlyItsPeers(t *testing.T) {
	p := standalonePolicy()
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	chains := build(p)
	capture := ruleNames(chains[1])
	wantCapture := []string{"pod-local", "mesh-sockets", "capture-peer-203.0.113.7-8080", "capture-peer-198.51.100.9-443"}
	if chains[1].name != "capture-outbound" || !slices.Equal(capture, wantCapture) {
		t.Fatalf("%s rules = %v, want %v", chains[1].name, capture, wantCapture)
	}
	output := ruleNames(chains[3])
	if chains[3].name != "filter-output" || output[0] != "deny-link-local" || !slices.Equal(output[len(output)-3:], []string{"pod-local", "pod-egress-6", "pod-egress-17"}) {
		t.Fatalf("%s rules = %v", chains[3].name, output)
	}
	for _, refused := range []string{"namespace-entrant", "mesh-sockets", "resolver-10.53.0.10-udp", "resolver-10.53.0.10-tcp"} {
		if slices.Contains(output, refused) {
			t.Errorf("a standalone Pod's output holds rule %s", refused)
		}
	}
	member := listenerOwnerRules(testPolicy())
	for i, r := range listenerOwnerRules(p) {
		established := len(r.exprs) > len(member[i].exprs)
		if established != strings.HasPrefix(r.name, "mesh-listener-") {
			t.Errorf("listener rule %s: restricted to established flows = %v", r.name, established)
		}
	}
}

// A peer the endpoint could not dial as a remote IPv4 tuple is refused.
func TestStandalonePodRefusesAPeerItCannotReach(t *testing.T) {
	for _, peer := range []Destination{
		{netip.MustParseAddr("127.0.0.1"), 8080},
		{netip.MustParseAddr("10.255.254.1"), 8080},
		{netip.MustParseAddr("2001:db8::7"), 8080},
		{netip.MustParseAddr("203.0.113.7"), 0},
	} {
		p := standalonePolicy()
		p.Pod.Peers = append(p.Pod.Peers, peer)
		if err := p.validate(); !errors.Is(err, ErrPolicy) {
			t.Errorf("peer %v: error = %v, want ErrPolicy", peer, err)
		}
	}
}
