package cdsha

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// A recover whose Raft cannot shut down (a read barrier stranded behind a
// state machine that never finishes) starts no new Raft generation over
// it: the replica stops, and its process ends (Run returns ErrStuck).
func TestRecoverPastAStrandedBarrierEndsRun(t *testing.T) {
	key, pub := operatorKey(t)
	ds := newMemDecrees()
	n, err := NewNode(soloConfig(t, "stalled", freeAddr(t), pub, ds))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	n.shutdown()
	held := &heldReadFSM{FSM: n.fsm, entered: make(chan struct{}), release: make(chan struct{})}
	trans, err := n.transport()
	if err != nil {
		t.Fatal(err)
	}
	r, err := raft.NewRaft(n.rcfg, held, n.logs, n.stable, n.snaps, trans)
	if err != nil {
		t.Fatal(err)
	}
	n.rft.Store(r)
	var release sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	t.Cleanup(func() { release.Do(func() { close(held.release) }); cancel() })
	ds.put(signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "stalled", TargetMember: n.ID(), Alone: true}))
	eventually(t, 10*time.Second, "stalled test leader serves", n.Serving)
	held.hold.Store(true)
	go func() { _ = r.Apply([]byte(`{}`), time.Second).Error() }()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("FSM not held")
	}
	if _, err := n.readBarrier(r, 20*time.Millisecond); err == nil {
		t.Fatal("blocked Barrier succeeded")
	}
	n.recover(ctx, PendingDecree{Name: "test-recover"})
	if n.r() != r {
		t.Fatal("recover started a new Raft generation over one that did not shut down")
	}
	if !n.fsm.StuckLocal() {
		t.Fatalf("stuck = %q, local %v", n.fsm.Stuck(), n.fsm.StuckLocal())
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrStuck) {
			t.Fatalf("Run returned %v, want ErrStuck", err)
		}
	case <-time.After(n.cfg.Timing.DeadAfter + 2*n.cfg.Timing.Apply + 2*time.Second):
		t.Fatal("the replica kept running over a Raft that did not shut down")
	}
}
