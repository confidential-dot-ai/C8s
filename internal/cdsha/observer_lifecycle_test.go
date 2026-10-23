package cdsha

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestHeartbeatObserverJoinsEachGeneration(t *testing.T) {
	_, pub := operatorKey(t)
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.shutdown()
	for i := 0; i < 3; i++ {
		worker := n.observer
		if worker == nil {
			t.Fatal("missing observer")
		}
		select {
		case <-worker.done:
			t.Fatal("worker already stopped")
		default:
		}
		n.shutdown()
		select {
		case <-worker.done:
		case <-time.After(time.Second):
			// Instrumented old behavior has no owner cancellation; clean it up.
			worker.cancel()
			<-worker.done
			t.Fatal("shutdown left observer running")
		}
		if i < 2 {
			if err := n.startRaft(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestHeartbeatObserverRejectsStaleGeneration(t *testing.T) {
	_, pub := operatorKey(t)
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.shutdown()
	old := n.r()
	n.shutdown()
	if err := n.startRaft(); err != nil {
		t.Fatal(err)
	}
	current := n.r()
	// The current observation after the stale one is an explicit processing
	// fence. It also proves the consumer is active, not just refusing all input.
	ch := make(chan raft.Observation, 3)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); n.observe(ctx, current, ch) }()
	defer func() { cancel(); <-done }()
	ch <- raft.Observation{Raft: old, Data: raft.FailedHeartbeatObservation{PeerID: "stale"}}
	ch <- raft.Observation{Raft: current, Data: raft.FailedHeartbeatObservation{PeerID: "current"}}
	eventually(t, time.Second, "current observation", func() bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		_, ok := n.failing["current"]
		return ok
	})
	n.mu.Lock()
	_, stale := n.failing["stale"]
	n.mu.Unlock()
	if stale {
		t.Fatal("old generation changed failure bookkeeping")
	}
	// A retired worker must reject even a queued current-generation message.
	retired := make(chan raft.Observation, 1)
	retired <- raft.Observation{Raft: old, Data: raft.FailedHeartbeatObservation{PeerID: "retired"}}
	close(retired)
	n.observe(context.Background(), old, retired)
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.failing["retired"]; ok {
		t.Fatal("retired worker changed current state")
	}
}
