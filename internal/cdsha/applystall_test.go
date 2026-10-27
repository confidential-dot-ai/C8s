package cdsha

import (
	"strings"
	"testing"
	"time"
)

// A follower whose state machine hangs on a command still answers Raft
// heartbeats. It must not keep its vote and count as a filled seat while it
// applies nothing: it stops (local) and, the others keeping a majority,
// leaves, so the leader sees the seat empty and replaces it.
func TestFollowerWithHungApplyLeaves(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	f := followers(c)[0]
	f.node.fsm.applyDelay.Store(int64(2 * (testTiming.DeadAfter + testTiming.Apply)))
	t.Cleanup(func() { f.node.fsm.applyDelay.Store(0) })
	if err := l.al.PutWorkload("w", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, testTiming.DeadAfter+testTiming.Apply+20*testTiming.Tick, "the hung follower stopped", func() bool {
		return f.node.fsm.StuckLocal() && strings.Contains(f.node.fsm.Stuck(), "has not finished")
	})
	select {
	case <-f.done:
	case <-time.After(testTiming.Lease + 3*testTiming.Apply):
		t.Fatal("the hung follower kept running")
	}
	eventually(t, testTiming.DeadAfter+time.Second, "the leader reports the seats unfilled", func() bool {
		return !l.node.Status().SeatsFilled
	})
}
