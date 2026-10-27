package cdsha

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// hashicorp/raft#696. Raft v1.8 queues a leadership transfer in the
// target's replicator (one slot) until the replicator's RPC in flight
// returns; a second transfer to that target meanwhile blocks the transfer
// monitor, and the leader refuses every Apply and Barrier until the slot
// drains (for good if it steps down first).

// busyFollower picks the leader L, a follower F whose Raft thread is held
// inside AppendEntries (its state machine queue is full: slow applies plus a
// burst of writes, as a slow disk does) while heartbeats still flow, and the
// other follower G.
func busyFollower(t *testing.T, c *cluster) (l, f, g *replica, fServer raft.Server) {
	t.Helper()
	l = c.leader()
	for _, r := range c.live() {
		switch {
		case r == l:
		case f == nil:
			f = r
		default:
			g = r
		}
	}
	for _, s := range l.node.servers() {
		if string(s.ID) == f.node.ID() {
			fServer = s
		}
	}
	slowApply(t, 30*time.Second, f)
	for i := 0; i < 300; i++ {
		if err := l.al.PutWorkload(fmt.Sprintf("w%d", i%4), mkWorkload(t, i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	return l, f, g, fServer
}

// The slow-leader path, asked twice in a row to hand leadership to a busy
// follower, transfers once: the leader takes writes and barriers again
// within a transfer timeout instead of refusing them until the slot drains
// (~8.6 s on 0e39637).
func TestSlowLeaderTransferNeverRepeatsToBusyTarget(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l, _, _, fs := busyFollower(t, c)
	lr := l.node.r()
	for i := 0; i < 2; i++ {
		l.node.membershipMu.Lock()
		l.node.transferSlowLeader(lr, &fs, nil)
		l.node.membershipMu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	start := time.Now()
	var err error
	for time.Since(start) < testTiming.Election+time.Second {
		if err = lr.Barrier(time.Second).Error(); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("leader with a live quorum still refuses barriers %v after two transfers to a busy follower: %v", time.Since(start).Round(time.Millisecond), err)
	}
	if lr.State() != raft.Leader {
		t.Fatalf("leader stepped down: %v", lr.State())
	}
	if err := l.al.PutWorkload("after", mkWorkload(t, 1000)); err != nil {
		t.Fatalf("write after the transfers: %v", err)
	}
}

// A stuck leader hands leadership only to a caught-up, responsive voter: not
// to a follower whose log lags (the #696 trigger), and to none when that is
// all there is.
func TestStuckTransferTargetSkipsBusyFollower(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	// A follower learns the commit index on the next AppendEntries (within
	// CommitTimeout), so one probe can just miss it: the stuck leader tries
	// again every Tick.
	l := c.leader()
	eventually(t, 2*time.Second, "negative control: a target in a healthy cluster", func() bool {
		return l.node.stuckTransferTarget(l.node.r(), l.node.servers()) != nil
	})
	l, f, g, _ := busyFollower(t, c)
	sawG := false
	for i := 0; i < 20; i++ {
		tg := l.node.stuckTransferTarget(l.node.r(), l.node.servers())
		if tg != nil && string(tg.ID) == f.node.ID() {
			t.Fatalf("target is the busy follower %s", f.node.ID())
		}
		sawG = sawG || tg != nil
		time.Sleep(testTiming.Tick)
	}
	if !sawG {
		t.Fatalf("never picked the caught-up follower %s", g.node.ID())
	}
	c.stopReplica(g)
	for i := 0; i < 10; i++ {
		if tg := l.node.stuckTransferTarget(l.node.r(), l.node.servers()); tg != nil {
			t.Fatalf("target %s with only a busy follower left", tg.ID)
		}
		time.Sleep(testTiming.Tick)
	}
}

// A transfer to the same target is refused within the cooldown; another
// target is not.
func TestTransferCooldownIsPerTarget(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l, _, g, fs := busyFollower(t, c)
	lr := l.node.r()
	l.node.membershipMu.Lock()
	defer l.node.membershipMu.Unlock()
	_ = l.node.transferLeadership(lr, fs) // times out: F is busy
	if err := l.node.transferLeadership(lr, fs); !errors.Is(err, errTransferCooldown) {
		t.Fatalf("second transfer to the busy follower: %v", err)
	}
	var gs raft.Server
	for _, s := range l.node.servers() {
		if string(s.ID) == g.node.ID() {
			gs = s
		}
	}
	// Raft itself refuses any transfer until the first one's monitor ends;
	// such a refusal queues nothing and starts no cooldown.
	eventually(t, 15*time.Second, "transfer to G", func() bool { return l.node.transferLeadership(lr, gs) == nil })
	eventually(t, 5*time.Second, "G leads", func() bool { return g.node.r().State() == raft.Leader })
}

// The leader-progress watchdog: raft refuses every barrier of a leader whose
// quorum answers (two raw transfers to a busy follower, past our guard), so
// Run ends after DeadAfter instead of leading while refusing everything.
func TestLeaderWedgedByTransferRefusalExits(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l, _, _, fs := busyFollower(t, c)
	lr := l.node.r()
	e1 := lr.LeadershipTransferToServer(fs.ID, fs.Address).Error()
	time.Sleep(200 * time.Millisecond)
	e2 := lr.LeadershipTransferToServer(fs.ID, fs.Address).Error()
	time.Sleep(300 * time.Millisecond)
	e3 := lr.Barrier(time.Second).Error()
	t.Logf("transfer 1: %v; transfer 2: %v; barrier right after: %v", e1, e2, e3)
	if !errors.Is(e3, raft.ErrLeadershipTransferInProgress) {
		t.Skipf("replicator was not busy (barrier %v): precondition not met", e3)
	}
	select {
	case <-l.done:
		t.Logf("Run ended: %v", l.err)
		if l.err == nil {
			t.Fatal("Run ended without an error")
		}
	// Run returns once Raft has shut down, at most Timing.Apply.
	case <-time.After(testTiming.DeadAfter + testTiming.Lease + testTiming.Apply + time.Second):
		t.Fatalf("wedged leader still runs (state %v, barrier %v)", lr.State(), lr.Barrier(time.Second).Error())
	}
}

// Negative control: one transfer to a busy follower holds raft's transfer
// flag only until the transfer times out; the leader keeps leading and Run
// goes on.
func TestSingleTransferDoesNotTripWedgedWatchdog(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l, _, _, fs := busyFollower(t, c)
	lr := l.node.r()
	t.Logf("transfer: %v", lr.LeadershipTransferToServer(fs.ID, fs.Address).Error())
	select {
	case <-l.done:
		t.Fatalf("Run ended after one transfer: %v", l.err)
	case <-time.After(2*testTiming.DeadAfter + testTiming.Lease):
	}
	if lr.State() != raft.Leader {
		t.Fatalf("leader lost leadership: %v", lr.State())
	}
	if err := lr.Barrier(time.Second).Error(); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	if err := l.node.wedged(); err != nil {
		t.Fatal(err)
	}
}
