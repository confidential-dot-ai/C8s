//go:build linux

package ruleset

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/nftables/expr"
)

// The guest forwards a Pod's ordinary egress, but never a Pod-originated
// packet to an advertised peer tuple: those connections are the guest's own
// .
func TestGuestForwardDeniesPeerTuplesBeforeOrdinaryEgress(t *testing.T) {
	policy := GuestPolicy{Bridge: "c8spod0", PodAddress: netip.MustParseAddr("10.255.254.2"),
		Peers: []Destination{{Addr: netip.MustParseAddr("203.0.113.1"), Port: 15006}}, IngressPorts: []uint16{8080}}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(buildGuest(policy), func(c chain) bool { return c.name == "guest-forward" })
	if index < 0 {
		t.Fatal("no guest-forward chain")
	}
	forward := buildGuest(policy)[index]
	names := make([]string, len(forward.rules))
	for i, r := range forward.rules {
		names[i] = r.name
	}
	deny, egress := slices.Index(names, "deny-peer-203.0.113.1-15006"), slices.Index(names, "pod-egress-6")
	if deny < 0 || egress < 0 || deny > egress {
		t.Fatalf("peer denial does not precede Pod egress: %v", names)
	}
	verdict, ok := forward.rules[deny].exprs[len(forward.rules[deny].exprs)-1].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop {
		t.Fatalf("peer tuple rule verdict = %#v, want drop", forward.rules[deny].exprs[len(forward.rules[deny].exprs)-1])
	}
}
