package cdsha

import (
	"testing"
	"time"
)

// A Recover decree on a cluster whose leader holds a majority is refused,
// with a reason, even when it names a replica that is cut off; nothing
// changes, and the cut-off replica rejoins after the heal.
func TestRecoverRefusedWithQuorum(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	var cut *replica
	for _, r := range c.live() {
		if r != l {
			cut = r
			break
		}
	}
	c.partition(cut.name, true)
	eventually(t, 4*time.Second, "cut-off replica stops serving", func() bool { return !cut.node.Serving() })
	epoch := l.node.Core().Epoch
	rec := c.decree(Decree{Kind: Recover, BootstrapNode: cut.name, BaseEpoch: epoch})
	eventually(t, 5*time.Second, "recover refused", func() bool { _, ok := c.decrees.get(rec); return ok })
	if st, _ := c.decrees.get(rec); st.AppliedEpoch != nil || st.RejectedReason != ErrRecoverWithQuorum.Error() {
		t.Fatalf("Recover with a quorum: %+v", st)
	}
	// Past dead_after the cut-off replica must not recover itself either.
	time.Sleep(testTiming.DeadAfter + 500*time.Millisecond)
	if cut.node.r().State().String() == "Leader" || l.node.Core().Epoch != epoch {
		t.Fatalf("Recover took effect: cut-off state %s, epoch %d -> %d", cut.node.r().State(), epoch, l.node.Core().Epoch)
	}
	c.partition(cut.name, false)
	c.settled(15 * time.Second)
	if e := c.leader().node.Core().Epoch; e != epoch {
		t.Fatalf("epoch moved %d -> %d", epoch, e)
	}
}
