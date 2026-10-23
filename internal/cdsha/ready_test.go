package cdsha

import (
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// Ready (what a rolling restart waits for) holds back a restarted voter
// that serves as a new non-voter until the seats are full again; the
// others stay Ready.
func TestReadyWaitsForTheSeats(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2", "n3")
	eventually(t, 10*time.Second, "every replica ready", func() bool {
		for _, r := range c.live() {
			if !r.node.Ready() {
				return false
			}
		}
		return true
	})
	l := c.leader()
	var voter *replica
	for _, r := range c.live() {
		if r != l && r.node.isVoter() {
			voter = r
		}
	}
	c.stopReplica(voter)
	back := c.start(voter.name, "m1")
	early := false
	eventually(t, 15*time.Second, "restarted voter ready", func() bool {
		ready := back.node.Ready()
		if ready && !back.node.isVoter() {
			if st := c.leader().node.Status(); len(st.Voters) < 3 {
				early = true
			}
		}
		return ready
	})
	if early {
		t.Fatal("a restarted voter was Ready as a non-voter while a seat was free")
	}
	if st := c.leader().node.Status(); !st.SeatsFilled || len(st.Voters) != 3 {
		t.Fatalf("leader reports seats filled %v with %d voters", st.SeatsFilled, len(st.Voters))
	}
	// A voter failing heartbeats leaves its seat unfilled.
	l = c.leader()
	other := slices.DeleteFunc(l.node.Status().Voters, func(id string) bool { return id == l.node.ID() })[0]
	l.node.mu.Lock()
	l.node.failing[raft.ServerID(other)] = time.Now()
	l.node.mu.Unlock()
	if l.node.seatsFilled() {
		t.Fatal("seats filled with a failing voter")
	}
}
