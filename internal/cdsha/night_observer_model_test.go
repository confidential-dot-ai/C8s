package cdsha

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// The unbuffered send proves observe has received the event. Holding n.mu
// prevents its cancellation/generation guard from running until after cancel.
// Unlike a sleep, this fence cannot pass without the real handler receiving.
func TestNightObserverCancelWhileHandlerWaitsForMutex(t *testing.T) {
	_, pub := operatorKey(t)
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.shutdown()
	current := n.r()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan raft.Observation)
	done := make(chan struct{})
	go func() { defer close(done); n.observe(ctx, current, ch) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("observer cleanup did not finish")
		}
	}()

	// Positive control on the same handler and generation.
	select {
	case ch <- raft.Observation{Raft: current, Data: raft.FailedHeartbeatObservation{PeerID: "healthy-fence"}}:
	case <-time.After(time.Second):
		t.Fatal("healthy observation not received")
	}
	eventually(t, time.Second, "healthy observation processed", func() bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		_, ok := n.failing["healthy-fence"]
		return ok
	})

	n.mu.Lock()
	select {
	case ch <- raft.Observation{Raft: current, Data: raft.FailedHeartbeatObservation{PeerID: "cancelled-inflight"}}:
		// The handler cannot check ctx.Err until we unlock below.
	case <-time.After(time.Second):
		n.mu.Unlock()
		t.Fatal("inflight observation not received")
	}
	cancel()
	// A handler already blocked on n.mu cannot complete yet. This is a
	// synchronous check, not a claim that arbitrary cancellation is bounded.
	select {
	case <-done:
		n.mu.Unlock()
		t.Fatal("observer completed while its received handler could not acquire mutex")
	default:
	}
	n.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled observer did not finish after mutex release")
	}
	n.mu.Lock()
	_, admitted := n.failing["cancelled-inflight"]
	n.mu.Unlock()
	if admitted {
		t.Fatal("cancelled inflight observation mutated failure bookkeeping")
	}
}
