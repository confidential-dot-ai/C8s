package secrets

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

type secretFanout struct {
	mu     sync.Mutex
	stores []*MemoryStore
	self   int
}

func (f *secretFanout) ReplicateSecret(cmd Command) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var mine Result
	for i, s := range f.stores {
		if r := s.Apply(cmd); i == f.self {
			mine = r
		}
	}
	return mine, nil
}

// Two replicas generating a value for one path: the first committed wins at
// both, and both callers are handed it. Quotas decide alike everywhere.
func TestReplicatedSecretsFirstWriterWinsEverywhere(t *testing.T) {
	mem := []*MemoryStore{NewMemoryStore(4, 2, 64), NewMemoryStore(4, 2, 64)}
	a := ReplicatedStore{mem[0], &secretFanout{stores: mem, self: 0}}
	b := ReplicatedStore{mem[1], &secretFanout{stores: mem, self: 1}}
	ctx := context.Background()
	w := WorkloadHolder("web")
	got, held, err := a.PutIfAbsent(ctx, "/p", []byte("from-a"), w)
	if err != nil || held.Exists || string(got) != "from-a" {
		t.Fatalf("first: %q %+v %v", got, held, err)
	}
	got, held, err = b.PutIfAbsent(ctx, "/p", []byte("from-b"), w)
	if err != nil || !held.Exists || string(got) != "from-a" {
		t.Fatalf("second writer must get the first value: %q %+v %v", got, held, err)
	}
	if _, _, err := b.PutIfAbsent(ctx, "/q", []byte("v"), w); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.PutIfAbsent(ctx, "/r", []byte("v"), w); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("quota counted per replica, not cluster-wide: %v", err)
	}
	if _, err := b.Put(ctx, "/p", []byte("operator")); err != nil {
		t.Fatal(err)
	}
	for i, m := range mem {
		v, err := m.Get(ctx, "/p")
		if err != nil || !bytes.Equal(v, []byte("operator")) || m.Len() != 2 {
			t.Fatalf("replica %d: %q len %d %v", i, v, m.Len(), err)
		}
	}
	if _, err := a.Put(ctx, "/big", bytes.Repeat([]byte("x"), 65)); err == nil {
		t.Fatal("oversized value replicated")
	}
	fresh := NewMemoryStore(4, 2, 64)
	fresh.Restore(mem[0].Dump())
	if v, _ := fresh.Get(ctx, "/q"); string(v) != "v" || fresh.Len() != 2 {
		t.Fatal("snapshot lost a path")
	}
	// /p moved to the operator, so web holds one path: one more fits, then
	// the quota answers, as it would have before the snapshot.
	rf := ReplicatedStore{fresh, &secretFanout{stores: []*MemoryStore{fresh}}}
	if _, _, err := rf.PutIfAbsent(ctx, "/s", []byte("v"), w); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rf.PutIfAbsent(ctx, "/t", []byte("v"), w); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("restored store forgot the holder's quota: %v", err)
	}
}
