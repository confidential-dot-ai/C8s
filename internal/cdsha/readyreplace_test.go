package cdsha

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// While a dead voter is replaced (add, then remove), a majority serves, so
// some replica must stay Ready: Ready is also Service membership. The voters
// that held their seats stay Ready; the promoted replacement is not Ready
// until the dead voter retired, so a rollout still waits for it.
func TestSeatedVotersStayReadyDuringReplacement(t *testing.T) {
	c := newCluster(t, 3)
	var mute atomic.Value // the nodes whose status replies fail
	mute.Store([]string(nil))
	gate := func(name string) func(controlHandler) controlHandler {
		return func(next controlHandler) controlHandler {
			return func(peer Claims, req controlRequest) controlResponse {
				if req.Op == ctlStatus && slices.Contains(mute.Load().([]string), name) {
					return controlResponse{Err: "test: status unavailable"}
				}
				return next(peer, req)
			}
		}
	}
	for _, name := range []string{"n0", "n1", "n2"} {
		c.startWithControl(name, "m1", gate(name))
	}
	gd := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	eventually(t, 10*time.Second, "genesis applied", func() bool { st, ok := c.decrees.get(gd); return ok && st.AppliedEpoch != nil })
	c.settled(15 * time.Second)
	nv := c.startWithControl("n3", "m1", gate("n3"))
	c.settled(15 * time.Second)
	eventually(t, 10*time.Second, "every replica Ready", func() bool {
		for _, r := range c.live() {
			if !r.node.Ready() {
				return false
			}
		}
		return true
	})
	l := c.leader()
	others := c.others(l)
	var dead, stay *replica
	for _, r := range others {
		switch {
		case r == nv:
		case dead == nil:
			dead = r
		default:
			stay = r
		}
	}
	// stay does not answer status: the leader cannot retire the dead voter
	// (retireVoters), so the extra voter stays and the window stays open.
	mute.Store([]string{stay.name})
	c.stopReplica(dead)
	promoted := false
	deadline := time.Now().Add(testTiming.DeadAfter + 10*time.Second)
	var openFor time.Duration
	for last := time.Now(); time.Now().Before(deadline) && openFor < 2*time.Second; last = time.Now() {
		time.Sleep(10 * time.Millisecond)
		if l.node.voterCount() > c.seats {
			promoted = true
			openFor += time.Since(last)
			if nv.node.Ready() {
				t.Fatal("the promoted replacement is Ready while the dead voter still votes")
			}
		}
		ready := 0
		for _, r := range c.live() {
			if r.node.Ready() {
				ready++
			}
		}
		if ready == 0 {
			t.Fatalf("no replica Ready (voters %d, seats %d)", l.node.voterCount(), c.seats)
		}
	}
	if !promoted {
		t.Fatal("the non-voter was never promoted")
	}
	mute.Store([]string(nil))
	c.settled(30 * time.Second)
	eventually(t, 10*time.Second, "the replacement is Ready", nv.node.Ready)
}
