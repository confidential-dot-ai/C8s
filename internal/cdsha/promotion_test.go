package cdsha

import (
	"slices"
	"sync"
	"testing"
	"time"
)

// A promotion can commit through the leader and the promoted member alone.
// Until every voter holds it, the promoted member is not Ready (a rollout
// must not take the leader then: the voter that missed the promotion would
// refuse the new voter's votes for good) and no other member is promoted.
// Once the lagging voter catches up, the seats fill, and Ready holds steady.
func TestPromotionWaitsForEveryVoter(t *testing.T) {
	tm := testTiming
	tm.Stabilize = time.Second // room to stall y before a member is promoted
	// No backup write is in flight while y is stalled: one that cannot
	// commit without y would hold the leader loop.
	tm.Backup = time.Hour
	c := newCluster(t, 4)
	c.timing = &tm
	c.genesis("n0", "n2")
	l := c.leader()
	y := c.others(l)[0]
	x, z := c.start("n1", "m1"), c.start("n3", "m1")
	for _, r := range []*replica{l, y} {
		eventually(t, 10*time.Second, r.name+" holds n1 and n3", func() bool {
			nv := r.node.Status().NonVoters
			return slices.Contains(nv, x.node.ID()) && slices.Contains(nv, z.node.ID())
		})
	}
	// y's log store stalls: y answers heartbeats on Raft's fast path, so the
	// leader keeps its lease, but stores and acknowledges no entry. y's
	// Status waits on the same lock, so it is not asked until the release.
	y.node.logs.mu.Lock()
	var release sync.Once
	unstall := func() { release.Do(y.node.logs.mu.Unlock) }
	t.Cleanup(unstall)
	var first *replica
	eventually(t, tm.Stabilize+20*tm.Tick, "one member promoted without "+y.name, func() bool {
		vs := l.node.Status().Voters
		for _, r := range []*replica{x, z} {
			if slices.Contains(vs, r.node.ID()) {
				first = r
				return true
			}
		}
		return false
	})
	second := x
	if first == x {
		second = z
	}
	for end := time.Now().Add(tm.Stabilize + 20*tm.Tick); time.Now().Before(end); time.Sleep(tm.Tick / 2) {
		if first.node.Ready() {
			t.Fatal("the promoted member is Ready while " + y.name + " lacks its promotion")
		}
		if slices.Contains(l.node.Status().Voters, second.node.ID()) {
			t.Fatal("a second member was promoted while " + y.name + " lacks the first promotion")
		}
	}
	unstall()
	all := []*replica{l, x, y, z}
	eventually(t, 10*time.Second, "every seat filled and every replica Ready", func() bool {
		if !l.node.Status().SeatsFilled {
			return false
		}
		for _, r := range all {
			if !r.node.Ready() {
				return false
			}
		}
		return true
	})
	for end := time.Now().Add(40 * tm.Tick); time.Now().Before(end); time.Sleep(tm.Tick / 2) {
		for _, r := range all {
			if !r.node.Ready() {
				t.Fatal(r.name + " left Ready in a settled cluster")
			}
		}
	}
}
