package sandboxledger

import (
	"errors"
	"fmt"
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

// lagging is a replica that has not applied pending yet; CatchUp applies it
// and then reports err.
type lagging struct {
	ledgerFanout
	pending []Command
	err     error
}

func (f *lagging) CatchUp() error {
	for _, cmd := range f.pending {
		f.ledgers[0].Apply(cmd)
	}
	f.pending = nil
	return f.err
}

// A miss catches up once and looks again, so a binding taken at another
// replica a moment ago is found; what the catch-up never applied stays a miss.
func TestReplicatedLookupCatchesUp(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	l := New(time.Hour, 4)
	l.now = func() time.Time { return now }
	for _, err := range []error{nil, errors.New("timed out after applying")} {
		f := &lagging{ledgerFanout: ledgerFanout{ledgers: []*Ledger{l}}, err: err}
		l.SetReplicator(f)
		id := fmt.Sprintf("sb-%v", err)
		f.pending = []Command{{SandboxID: id, Host: "10.0.0.1", AtMS: now.UnixMilli()}}
		if h, ok := l.Lookup(id); !ok || h != "10.0.0.1" {
			t.Fatalf("catch-up err %v: binding applied by the catch-up not found: %q %v", err, h, ok)
		}
		if _, ok := l.Lookup("never-bound"); ok {
			t.Fatalf("catch-up err %v: a binding nobody took was found", err)
		}
	}
}

type downLedger struct{ ledgerFanout }

func (*downLedger) ReplicateBinding(Command) (bool, error) { return false, errors.New("no leader") }

// A binding no replica committed is refused: another replica could give the
// sandbox to a second inventory.
func TestUnreplicatedBindingIsRefused(t *testing.T) {
	l := New(time.Hour, 4)
	l.SetReplicator(&downLedger{})
	if l.Record("sb", "10.0.0.1") {
		t.Fatal("a binding no replica committed was taken")
	}
}
