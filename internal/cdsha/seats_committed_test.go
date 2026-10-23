package cdsha

import (
	"slices"
	"testing"
	"time"
)

// A membership change is in the latest configuration before Raft commits
// it, and a leader that dies first loses it. While one is in flight the
// leader must not report the voter seats filled, or a readiness-gated
// rollout may restart a voter of what is really a two-voter configuration.
func TestSeatsNotFilledDuringMembershipChange(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2", "n3")
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	var nv *Node
	nonvoters := l.node.Status().NonVoters
	for _, r := range c.live() {
		if slices.Contains(nonvoters, r.node.ID()) {
			nv = r.node
		}
	}
	if nv == nil {
		t.Fatal("no nonvoter")
	}
	eventually(t, 10*time.Second, "seats filled and the nonvoter ready", func() bool {
		nv.refreshSeats()
		return l.node.Status().SeatsFilled && nv.Ready()
	})

	l.node.membershipMu.Lock() // a change the leader has not seen committed
	if l.node.Status().SeatsFilled || l.node.seatsFilled() {
		l.node.membershipMu.Unlock()
		t.Fatal("seats reported filled while a membership change is in flight")
	}
	nv.refreshSeats()
	ready := nv.Ready()
	l.node.membershipMu.Unlock()
	if ready {
		t.Fatal("non-voter ready while the leader's membership change is in flight")
	}

	eventually(t, 10*time.Second, "seats filled again once the change is done", func() bool {
		nv.refreshSeats()
		return l.node.Status().SeatsFilled && nv.Ready()
	})
}
