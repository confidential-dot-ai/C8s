package cdsha

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/hashicorp/raft"
)

// writeLoad keeps writes flowing through every replica until stopped, so a
// slow state machine builds a backlog the read barrier has to wait for.
func writeLoad(t *testing.T, rs []*replica) (stop func()) {
	t.Helper()
	var wg sync.WaitGroup
	var seq atomic.Int64
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(r *replica) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				tok := expiryToken(time.Now().Unix(), fmt.Sprintf("load-%d", seq.Add(1)))
				_, _ = r.node.propose(Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, Token: tok}})
				time.Sleep(20 * time.Millisecond)
			}
		}(rs[i%len(rs)])
	}
	var once sync.Once
	stop = func() { once.Do(func() { close(done); wg.Wait() }) }
	t.Cleanup(stop)
	return stop
}

// slowApply makes replicas apply every command slowly, as a slow disk does,
// and undoes it before the cluster stops.
func slowApply(t *testing.T, d time.Duration, rs ...*replica) {
	for _, r := range rs {
		r.node.fsm.applyDelay.Store(int64(d))
	}
	t.Cleanup(func() {
		for _, r := range rs {
			r.node.fsm.applyDelay.Store(0)
		}
	})
}

// A leader whose own disk is slow keeps leadership (heartbeats never touch
// the disk) while its read barrier waits behind its apply backlog, so no
// replica can certify a read. It hands leadership to a replica that applies
// the log, and the cluster serves again.
func TestSlowLeaderTransfersLeadership(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	old := c.leader()
	if old == nil {
		t.Fatal("no leader")
	}
	rs := c.live()
	slowApply(t, 2*testTiming.Lease, old)
	stop := writeLoad(t, rs)
	eventually(t, 20*time.Second, "a replica with a fast disk leads and every other replica serves", func() bool {
		l := c.leader()
		if l == nil || l == old {
			return false
		}
		for _, r := range rs {
			if r != old && !r.node.Serving() {
				return false
			}
		}
		return true
	})
	stop()
	l := c.leader()
	if l == nil || l == old {
		t.Fatal("leadership went back to the slow replica")
	}
	if st := l.node.Status(); st.State != raft.Leader.String() {
		t.Fatalf("new leader status: %+v", st)
	}
	if _, err := l.node.propose(Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken,
		Token: expiryToken(time.Now().Unix(), "after-transfer")}}); err != nil {
		t.Fatalf("write through the new leader: %v", err)
	}
}

// When every replica is equally slow no follower is caught up, so leadership
// stays put instead of being passed around: a transfer would not help.
func TestUniformlySlowClusterKeepsLeader(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	rs := c.live()
	slowApply(t, 2*testTiming.Lease, rs...)
	writeLoad(t, rs)
	lead := c.leader()
	if lead == nil {
		t.Fatal("no leader")
	}
	term := lead.node.r().CurrentTerm()
	unavailable := false
	deadline := time.Now().Add(3*testTiming.DeadAfter + 3*testTiming.Lease)
	for time.Now().Before(deadline) {
		l := c.leader()
		if l != nil && (l != lead || l.node.r().CurrentTerm() != term) {
			t.Fatalf("leadership moved from %s (term %d) to %s (term %d) in a uniformly slow cluster",
				lead.name, term, l.name, l.node.r().CurrentTerm())
		}
		// The slow-leader condition holds except for a caught-up follower.
		if m := lead.node.readOK.Load(); m != nil && time.Since(m.start) > 2*testTiming.Lease && lead.node.Status().ApplyLag > 0 {
			unavailable = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !unavailable {
		t.Fatal("the leader never fell behind: the test did not exercise a slow cluster")
	}
}
