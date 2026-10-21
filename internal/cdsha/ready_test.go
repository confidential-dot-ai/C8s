package cdsha

import (
	"testing"
	"time"
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
	if !c.leader().node.Status().SeatsFilled {
		t.Fatal("leader does not report the seats filled")
	}
	if c.leader().node.Status().SeatsFilled && len(c.leader().node.Status().Voters) != 3 {
		t.Fatal("seats filled with fewer voters than seats")
	}
}
