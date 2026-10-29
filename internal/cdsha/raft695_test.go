//go:build raft695

package cdsha

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// hashicorp/raft #695 through our Node, transport and FSM. Built only with -tags raft695 -modfile=go.raft695.mod, which
// swaps in raft v1.8.0 plus one hook (TestHookBeforeDispatchTerm) that
// pauses the leader's main thread just before dispatchLogs reads the term.
// The deposed leader A pauses while dispatching a client write X; A is
// partitioned, B is elected at a newer term, the partition heals and B's
// heartbeats reach A; then A resumes. With Raft's heartbeat fast path the
// heartbeat raised A's term on the transport goroutine and A stamped X with
// B's term, so one replica applied and served a write the cluster never
// committed. With termSafeHeartbeats a heartbeat that would change A's term
// or role waits for A's main thread, A dispatches X at its own old term, and
// the new leader's log replaces it.
func TestRaft695NoDivergenceAfterHeal(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	a := c.leader()
	aID := raft.ServerID(a.node.ID())
	termA := a.node.r().CurrentTerm()
	var armed atomic.Bool
	paused, release := make(chan struct{}), make(chan struct{})
	raft.TestHookBeforeDispatchTerm = func(id raft.ServerID) {
		if id == aID && armed.CompareAndSwap(true, false) {
			close(paused)
			<-release
		}
	}
	t.Cleanup(func() { raft.TestHookBeforeDispatchTerm = nil })
	armed.Store(true)
	go func() { _ = a.al.PutWorkload("X", mkWorkload(t, 7)) }()
	<-paused
	lastA := a.node.r().LastIndex()
	t.Logf("leader %s paused before dispatch at term %d, last index %d", a.name, termA, lastA)

	c.partition(a.name, true)
	var b *replica
	eventually(t, 10*time.Second, "new leader in the majority", func() bool {
		for _, r := range c.live() {
			if r != a && r.node.r().State() == raft.Leader {
				b = r
				return true
			}
		}
		return false
	})
	termB := b.node.r().CurrentTerm()
	t.Logf("new leader %s at term %d", b.name, termB)
	c.partition(a.name, false)
	// B's heartbeats reach A; give them time to (not) change A's term.
	time.Sleep(10 * testTiming.Heartbeat)
	t.Logf("A, main thread still paused: term %d (fast path would have raised it to %d)", a.node.r().CurrentTerm(), termB)
	if a.node.r().CurrentTerm() >= termB {
		t.Errorf("a heartbeat changed the paused leader's term off its main thread")
	}
	close(release)

	idx := lastA + 1
	var la, lb raft.Log
	eventually(t, 10*time.Second, "B stored an entry at the index", func() bool { return b.node.logs.GetLog(idx, &lb) == nil })
	if err := b.al.PutWorkload("after", mkWorkload(t, 8)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * time.Second)
	if a.node.logs.GetLog(idx, &la) == nil {
		t.Logf("index %d: A term %d type %s %dB | B term %d type %s %dB", idx, la.Term, la.Type, len(la.Data), lb.Term, lb.Type, len(lb.Data))
		if la.Term == lb.Term && (la.Type != lb.Type || string(la.Data) != string(lb.Data)) {
			t.Errorf("LOG MATCHING VIOLATED: same (index %d, term %d), different entries", idx, la.Term)
		}
	}
	have := 0
	for _, r := range c.live() {
		st := r.node.Status()
		t.Logf("%s state=%s term=%d applied=%d serving=%v stuck=%.60q holds X=%v", r.name, st.State, st.Term, st.AppliedIndex, st.Serving, st.Stuck, holds(r, "X"))
		if holds(r, "X") {
			have++
		}
		if st.Serving && holds(r, "X") && !holds(b, "X") {
			t.Errorf("%s serves X, which the cluster never committed", r.name)
		}
	}
	if have != 0 && have != len(c.live()) {
		t.Errorf("FSM DIVERGENCE: %d of %d replicas hold X", have, len(c.live()))
	}
}
