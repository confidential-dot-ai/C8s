package cdsha

import (
	"testing"
	"time"
)

// An idle replica reads its store every T/2, with no client asking: that
// read writes a rolled-back store forward and notices another chain.
func TestIdleReplicaReadsTheStoreEveryHalfT(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	counting := &countingStore{Store: s.store}
	s.node(0).setStore(counting)
	time.Sleep(10 * T)
	if n := counting.reads.Load(); n < 10 {
		t.Fatalf("%d store reads in 10 T, want one every T/2", n)
	}
}

// A pending replica whose store already holds a chain waits for a giver:
// it no longer offers itself for a genesis, but still publishes its key.
func TestPendingReplicaOverAChainIsNoGenesis(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	n := s.boot(0, buildA)
	s.waitFor("the new instance to find the store's chain", func() bool {
		p, err := n.Pending(true)
		return err == nil && p == nil
	})
	if p, err := n.Pending(false); err != nil || p == nil {
		t.Fatalf("a joiner publishes nothing for a giver: %v", err)
	}
}
