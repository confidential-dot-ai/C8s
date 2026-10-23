package cdsha

import (
	"errors"
	"testing"
	"time"
)

// A stuck replica ends Run, so its process exits and is restarted: a
// transient local fault must not take it out of the cluster for good.
func TestStuckFollowerEndsRun(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	var f *replica
	for _, r := range c.live() {
		if r != l {
			f = r
			break
		}
	}
	f.node.fsm.stop(errors.New("test: local store fault"))
	select {
	case <-f.done:
	case <-time.After(testTiming.Lease + 5*testTiming.Tick + 2*time.Second):
		t.Fatal("stuck follower kept running")
	}
}

// A stuck leader hands off leadership before it ends Run.
func TestStuckLeaderHandsOffThenEndsRun(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	old := c.leader()
	if old == nil {
		t.Fatal("no leader")
	}
	old.node.fsm.stop(errors.New("test: local store fault"))
	handedOff := false
	deadline := time.After(testTiming.DeadAfter + 5*testTiming.Tick + 2*time.Second)
	for {
		select {
		case <-old.done:
			if !handedOff {
				t.Fatal("stuck leader ended Run before another replica led")
			}
			return
		case <-deadline:
			t.Fatalf("stuck leader kept running (handed off: %v)", handedOff)
		case <-time.After(10 * time.Millisecond):
		}
		if l := c.leader(); l != nil && l != old {
			handedOff = true
		}
	}
}
