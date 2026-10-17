package sandboxledger

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type ledgerFanout struct {
	mu      sync.Mutex
	ledgers []*Ledger
	self    int
	writes  int
}

func (f *ledgerFanout) CatchUp() error { return nil }

func (f *ledgerFanout) ReplicateBinding(cmd Command) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	var mine bool
	for i, l := range f.ledgers {
		if r := l.Apply(cmd); i == f.self {
			mine = r
		}
	}
	return mine, nil
}

// A binding taken at one replica is the binding at every replica; a second
// inventory is refused everywhere; renewals do not each cost a write.
func TestReplicatedBindingHoldsEverywhere(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	a, b := New(time.Hour, 10), New(time.Hour, 10)
	for _, l := range []*Ledger{a, b} {
		l.now = func() time.Time { return now }
	}
	fa := &ledgerFanout{ledgers: []*Ledger{a, b}, self: 0}
	a.SetReplicator(fa)
	b.SetReplicator(&ledgerFanout{ledgers: []*Ledger{a, b}, self: 1})
	if !a.Record("sb1", "10.0.0.1") {
		t.Fatal("first binding refused")
	}
	if h, ok := b.Lookup("sb1"); !ok || h != "10.0.0.1" {
		t.Fatalf("binding missing at the other replica: %q %v", h, ok)
	}
	if b.Record("sb1", "10.0.0.66") {
		t.Fatal("a second inventory took the sandbox at another replica")
	}
	for range 5 {
		if !a.Record("sb1", "10.0.0.1") {
			t.Fatal("renewal refused")
		}
	}
	if fa.writes != 1 {
		t.Fatalf("renewals cost %d writes, want 1", fa.writes)
	}
	now = now.Add(40 * time.Minute)
	if !a.Record("sb1", "10.0.0.1") || fa.writes != 2 {
		t.Fatalf("late renewal must refresh the binding everywhere (writes %d)", fa.writes)
	}
	now = now.Add(50 * time.Minute)
	if _, ok := b.Lookup("sb1"); !ok {
		t.Fatal("the refresh did not reach the other replica")
	}
	c := New(time.Hour, 10)
	c.now = func() time.Time { return now }
	c.Restore(a.Dump())
	if h, ok := c.Lookup("sb1"); !ok || h != "10.0.0.1" {
		t.Fatal("snapshot lost the binding")
	}
}

type failingCatchUp struct{ ledgerFanout }

func (*failingCatchUp) CatchUp() error { return errors.New("no leader") }

// A miss catches up once; when that fails the lookup fails closed.
func TestReplicatedLookupFailsClosed(t *testing.T) {
	l := New(time.Hour, 4)
	l.SetReplicator(&failingCatchUp{})
	if _, ok := l.Lookup("sb"); ok {
		t.Fatal("a miss without catch-up reported a binding")
	}
}
