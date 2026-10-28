package cdsha

import (
	"errors"
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

// A host IO stall longer than the apply watchdog on every replica: each
// stops on the same command, none may leave (no majority follows the log).
// The command was slow, not skipped: once it returns, every replica follows
// the log again and the cluster serves without a restart.
func TestApplyStallOnEveryReplicaRecoversWithoutRestart(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	stall := testTiming.DeadAfter + testTiming.Apply + testTiming.DeadAfter + 2*testTiming.Lease
	for _, r := range c.live() {
		r.node.fsm.applyDelay.Store(int64(stall))
	}
	w := mkWorkload(t, 1)
	go func() { _ = l.al.PutWorkload("w", w) }()
	eventually(t, testTiming.DeadAfter+testTiming.Apply+20*testTiming.Tick, "every replica stalled", func() bool {
		for _, r := range c.live() {
			if !r.node.fsm.StuckLocal() {
				return false
			}
		}
		return true
	})
	for _, r := range c.live() {
		r.node.fsm.applyDelay.Store(0) // only the stalled command stays slow
	}
	eventually(t, stall+10*time.Second, "the cluster serves again", func() bool {
		ld := c.leader()
		if ld == nil || !ld.node.Serving() {
			return false
		}
		for _, r := range c.live() {
			if r.node.fsm.Stuck() != "" {
				return false
			}
		}
		return true
	})
	for _, r := range c.live() {
		if runEnded(r) {
			t.Fatalf("%s ended Run: %v", r.name, r.err)
		}
	}
	eventually(t, 10*time.Second, "a write after the stall", func() bool {
		ld := c.leader()
		return ld != nil && ld.al.PutWorkload("after", mkWorkload(t, 2)) == nil
	})
}

// A stall ends with its command, and only then: a stall raised after the
// command returned is taken back; a checkpoint applied during a stall keeps
// its state digest; a real stop raised during a stalled command stays, and
// no later checkpoint records a state digest.
func TestStallEndsOnlyWithItsCommand(t *testing.T) {
	_, pub := operatorKey(t)
	f := newTestFSM(t, pub)
	applyAt(f, 1, Entry{Kind: KindCheckpoint})
	f.stall(monoNow(), errors.New("test: stall of a command that returned"))
	if s := f.Stuck(); s != "" {
		t.Fatalf("a stall outlived its command: %s", s)
	}
	stalled := func(i uint64, during func()) {
		t.Helper()
		f.applyDelay.Store(int64(300 * time.Millisecond))
		defer f.applyDelay.Store(0)
		done := make(chan struct{})
		go func() { applyAt(f, i, Entry{Kind: KindCheckpoint}); close(done) }()
		eventually(t, time.Second, "the command started", func() bool { return f.applyStart.Load() != 0 })
		f.stall(f.applyStart.Load(), errors.New("test: stalled"))
		if !f.StuckLocal() {
			t.Fatal("no stall during the command")
		}
		during()
		<-done
	}
	stalled(2, func() {})
	if s := f.Stuck(); s != "" {
		t.Fatalf("the stall did not end with its command: %s", s)
	}
	if p := lastCheckpoint(t, f); p.Index != 2 || p.State == "" {
		t.Fatalf("checkpoint applied during a stall: %+v; want index 2 with a state digest", p)
	}
	stalled(3, func() { _ = f.stopLocal(errors.New("test: store fault")) })
	if s := f.Stuck(); !strings.Contains(s, "store fault") {
		t.Fatalf("stuck %q; want the store fault to stay", s)
	}
	applyAt(f, 4, Entry{Kind: KindCheckpoint})
	if p := lastCheckpoint(t, f); p.Index != 2 {
		t.Fatalf("a stopped replica recorded a state digest at checkpoint %d", p.Index)
	}
}
