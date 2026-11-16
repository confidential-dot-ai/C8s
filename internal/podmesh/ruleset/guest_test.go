//go:build linux

package ruleset

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func guestPolicy() GuestPolicy {
	return GuestPolicy{Bridge: "c8s-pod0", PodAddress: netip.MustParseAddr("10.255.254.2"), IngressPorts: []uint16{8080, 9090}}
}

// Guest policy a ruleset cannot express, or that would hand the Pod a
// platform port, is refused before any namespace is touched.
func TestGuestPolicyRefusesWhatARuleCannotExpress(t *testing.T) {
	tests := []struct {
		name  string
		spoil func(*GuestPolicy)
	}{
		{"no bridge", func(p *GuestPolicy) { p.Bridge = "" }},
		{"bridge name too long", func(p *GuestPolicy) { p.Bridge = strings.Repeat("b", 16) }},
		{"bridge name with a slash", func(p *GuestPolicy) { p.Bridge = "c8s/pod0" }},
		{"no Pod address", func(p *GuestPolicy) { p.PodAddress = netip.Addr{} }},
		{"IPv6 Pod address", func(p *GuestPolicy) { p.PodAddress = netip.MustParseAddr("fd00::2") }},
		{"loopback Pod address", func(p *GuestPolicy) { p.PodAddress = netip.MustParseAddr("127.0.0.2") }},
		{"ingress port zero", func(p *GuestPolicy) { p.IngressPorts = []uint16{8080, 0} }},
		{"ingress on the status port", func(p *GuestPolicy) { p.IngressPorts = []uint16{uint16(workloadclaims.PodStatusPort)} }},
		{"ingress on a mesh port", func(p *GuestPolicy) { p.IngressPorts = []uint16{uint16(workloadclaims.MeshHealthPort)} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := guestPolicy()
			tc.spoil(&p)
			if err := InstallGuest("/proc/self/ns/net", p); !errors.Is(err, ErrPolicy) {
				t.Fatalf("install error = %v, want ErrPolicy", err)
			}
			if err := VerifyGuest("/proc/self/ns/net", p); !errors.Is(err, ErrPolicy) {
				t.Fatalf("verify error = %v, want ErrPolicy", err)
			}
		})
	}
	if err := guestPolicy().validate(); err != nil {
		t.Fatalf("a valid guest policy was refused: %v", err)
	}
}

// The guest drops what the Pod sends to it, forwards only the Pod's own
// flows and the declared ingress ports, and translates each ingress port to
// the Pod address.
func TestGuestRulesetForwardsOnlyThePodsFlows(t *testing.T) {
	p := guestPolicy()
	chains := buildGuest(p)
	type shape struct {
		name   string
		kind   nftables.ChainType
		hook   nftables.ChainHook
		policy nftables.ChainPolicy
		rules  []string
	}
	want := []shape{
		{"guest-input", nftables.ChainTypeFilter, *nftables.ChainHookInput, nftables.ChainPolicyAccept,
			[]string{"probe-replies", "deny-pod-to-guest"}},
		{"guest-forward", nftables.ChainTypeFilter, *nftables.ChainHookForward, nftables.ChainPolicyDrop,
			[]string{"deny-link-local", "egress-replies", "egress-icmp-errors", "ingress-replies", "ingress-8080", "ingress-9090", "pod-egress-6", "pod-egress-17"}},
		{"guest-ingress", nftables.ChainTypeNAT, *nftables.ChainHookPrerouting, nftables.ChainPolicyAccept,
			[]string{"no-pod-hairpin", "ingress-8080", "ingress-9090"}},
		{"guest-egress", nftables.ChainTypeNAT, *nftables.ChainHookPostrouting, nftables.ChainPolicyAccept,
			[]string{"pod-egress-6", "pod-egress-17"}},
	}
	if len(chains) != len(want) {
		t.Fatalf("got %d chains, want %d", len(chains), len(want))
	}
	for i, c := range chains {
		names := make([]string, 0, len(c.rules))
		for _, r := range c.rules {
			names = append(names, r.name)
		}
		got := shape{c.name, c.kind, c.hook, c.policy, names}
		if got.name != want[i].name || got.kind != want[i].kind || got.hook != want[i].hook || got.policy != want[i].policy || !slices.Equal(got.rules, want[i].rules) {
			t.Errorf("chain %d = %+v, want %+v", i, got, want[i])
		}
	}
	for _, r := range chains[2].rules[1:] {
		immediate, nat := r.exprs[len(r.exprs)-2].(*expr.Immediate), r.exprs[len(r.exprs)-1].(*expr.NAT)
		if netip.AddrFrom4([4]byte(immediate.Data)) != p.PodAddress || nat.Type != expr.NATTypeDestNAT || nat.RegAddrMin != immediate.Register {
			t.Errorf("rule %s translates to %v with %+v", r.name, immediate.Data, nat)
		}
	}
	for _, r := range chains[3].rules {
		if _, ok := r.exprs[len(r.exprs)-1].(*expr.Masq); !ok {
			t.Errorf("rule %s does not masquerade", r.name)
		}
	}
	for _, c := range chains {
		for _, r := range c.rules {
			if _, err := marshalExpressions(r); err != nil {
				t.Errorf("rule %s of %s cannot be encoded: %v", r.name, c.name, err)
			}
		}
	}
}
