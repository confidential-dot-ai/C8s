package sandboxledger

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// cluster commits every binding to every replica's ledger and answers with
// what the handle's own ledger made of it.
type cluster struct {
	mu      sync.Mutex
	ledgers []*Ledger
	self    int
	commits int
}

func (c *cluster) CatchUp() {
}

func (c *cluster) Commit(cmd Command) (Held, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commits++
	var mine Held
	for i, l := range c.ledgers {
		if held := l.Apply(cmd); i == c.self {
			mine = held
		}
	}
	return mine, nil
}

// A binding taken at one replica holds at every replica, and a second
// inventory is refused everywhere.
func TestReplicatedBindingHoldsEverywhere(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	first := New(time.Hour, 10)
	second := New(time.Hour, 10)
	for _, l := range []*Ledger{first, second} {
		l.now = func() time.Time { return now }
	}
	ledgers := []*Ledger{first, second}
	a := first.CommittedBy(&cluster{
		ledgers: ledgers,
		self:    0,
	})
	b := second.CommittedBy(&cluster{
		ledgers: ledgers,
		self:    1,
	})

	if !a.Record("sb1", "10.0.0.1") {
		t.Fatal("first binding refused")
	}
	if host, ok := b.Lookup("sb1"); !ok || host != "10.0.0.1" {
		t.Fatalf("binding missing at the other replica: %q %v", host, ok)
	}
	if b.Record("sb1", "10.0.0.66") {
		t.Fatal("a second inventory took the sandbox at another replica")
	}
	if !a.Record("sb1", "10.0.0.1") {
		t.Fatal("the bound host was refused its own renewal")
	}
	now = now.Add(40 * time.Minute)
	if !a.Record("sb1", "10.0.0.1") {
		t.Fatal("renewal refused")
	}
	now = now.Add(50 * time.Minute)
	if _, ok := b.Lookup("sb1"); !ok {
		t.Fatal("the refresh did not reach the other replica")
	}
}

// A binding applies at the time the command carries, and its expiry never
// moves back.
func TestBindingAppliesAtTheStampedTime(t *testing.T) {
	stamped := time.UnixMilli(1_000_000)
	l := New(time.Hour, 10)
	l.now = func() time.Time { return stamped.Add(-30 * time.Minute) }

	if !l.Apply(Command{
		SandboxID: "sb1",
		Host:      "10.0.0.1",
		AtMS:      stamped.UnixMilli(),
	}) {
		t.Fatal("binding refused")
	}
	l.now = func() time.Time { return stamped.Add(90 * time.Minute) }
	if _, ok := l.bound("sb1"); ok {
		t.Fatal("a binding outlived the lifetime its command stamped")
	}

	l.now = func() time.Time { return stamped }
	behind := Command{
		SandboxID: "sb1",
		Host:      "10.0.0.1",
		AtMS:      stamped.Add(-45 * time.Minute).UnixMilli(),
	}
	if !l.Apply(behind) {
		t.Fatal("refresh refused")
	}
	l.now = func() time.Time { return stamped.Add(30 * time.Minute) }
	if _, ok := l.bound("sb1"); !ok {
		t.Fatal("a command stamped behind the binding moved its expiry back")
	}
}

// A command naming no sandbox or no host binds nothing.
func TestApplyRejectsAnEmptyCommand(t *testing.T) {
	l := New(time.Hour, 10)

	for _, cmd := range []Command{
		{
			SandboxID: "",
			Host:      "10.0.0.1",
			AtMS:      1,
		},
		{
			SandboxID: "sb1",
			Host:      "",
			AtMS:      1,
		},
	} {
		if l.Apply(cmd) {
			t.Fatalf("%+v was applied", cmd)
		}
	}
	if l.Len() != 0 {
		t.Fatalf("the ledger holds %d bindings, want none", l.Len())
	}
}

// lagging is a replica that has not applied pending yet: CatchUp applies it.
type lagging struct {
	cluster
	pending []Command
}

func (f *lagging) CatchUp() {
	for _, cmd := range f.pending {
		f.ledgers[f.self].Apply(cmd)
	}
	f.pending = nil
}

// A miss catches up once and looks again; what the catch-up never applied
// stays a miss.
func TestReplicatedLookupCatchesUp(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	l := New(time.Hour, 4)
	l.now = func() time.Time { return now }
	f := &lagging{cluster: cluster{ledgers: []*Ledger{l}}}
	h := l.CommittedBy(f)
	f.pending = []Command{{
		SandboxID: "sb1",
		Host:      "10.0.0.1",
		AtMS:      now.UnixMilli(),
	}}

	if host, ok := h.Lookup("sb1"); !ok || host != "10.0.0.1" {
		t.Fatalf("the binding the catch-up applied was not found: %q %v", host, ok)
	}
	if _, ok := h.Lookup("never-bound"); ok {
		t.Fatal("a binding nobody took was found")
	}
}

// noLeader is a cluster that cannot commit.
type noLeader struct{}

func (noLeader) CatchUp() {
}

func (noLeader) Commit(Command) (Held, error) {
	return false, errors.New("no leader")
}

// A binding the cluster did not commit is refused: another replica could
// still give the sandbox to a second inventory.
func TestUncommittedBindingIsRefused(t *testing.T) {
	l := New(time.Hour, 4).CommittedBy(noLeader{})

	if l.Record("sb", "10.0.0.1") {
		t.Fatal("a binding the cluster did not commit was taken")
	}
}

// A ledger drops nothing by its own clock: Len only counts, and the cap is
// what reclaims an expired binding.
func TestExpiredBindingsStayUntilACommandNeedsTheRoom(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	l := New(time.Hour, 2)
	l.now = func() time.Time { return now }
	h := l.CommittedBy(&cluster{ledgers: []*Ledger{l}})

	if !h.Record("sb1", "10.0.0.1") {
		t.Fatal("first binding refused")
	}
	now = now.Add(2 * time.Hour)
	if got := l.Len(); got != 0 {
		t.Fatalf("Len = %d live bindings, want 0", got)
	}
	if !h.Record("sb2", "10.0.0.2") || !h.Record("sb3", "10.0.0.3") {
		t.Fatal("the cap did not reclaim an expired binding")
	}
}

// Every replica reaches the same answer for the same commands, whatever its
// own clock says.
func TestReplicasAgreeOnWhatTheyHold(t *testing.T) {
	stamped := time.UnixMilli(1_000_000)
	ledgers := []*Ledger{New(time.Hour, 10), New(time.Hour, 10)}
	cmds := []Command{
		{
			SandboxID: "sb1",
			Host:      "10.0.0.1",
			AtMS:      stamped.UnixMilli(),
		},
		{
			SandboxID: "sb1",
			Host:      "10.0.0.66",
			AtMS:      stamped.Add(time.Minute).UnixMilli(),
		},
		{
			SandboxID: "sb2",
			Host:      "10.0.0.2",
			AtMS:      stamped.Add(2 * time.Minute).UnixMilli(),
		},
	}
	for i, l := range ledgers {
		l.now = func() time.Time { return stamped.Add(time.Duration(i) * time.Hour) }
	}

	answers := make([][]Held, len(ledgers))
	for i, l := range ledgers {
		for _, cmd := range cmds {
			answers[i] = append(answers[i], l.Apply(cmd))
		}
	}
	if fmt.Sprint(answers[0]) != fmt.Sprint(answers[1]) {
		t.Fatalf("replicas disagreed: %v and %v", answers[0], answers[1])
	}
	for i, l := range ledgers {
		if l.bindings["sb1"] != ledgers[0].bindings["sb1"] {
			t.Fatalf("replica %d holds %+v for sb1, replica 0 holds %+v", i, l.bindings["sb1"], ledgers[0].bindings["sb1"])
		}
	}
}

// A replica that joins a cluster takes every binding with its expiry,
// expired ones included: a replica drops one only when a command needs its
// room, so every replica holds the same set.
func TestASnapshotCarriesEveryBindingWithItsExpiry(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	source := New(time.Hour, 10)
	source.now = func() time.Time { return now }
	if !source.Local().Record("sb1", "10.0.0.1") {
		t.Fatal("binding refused")
	}
	if !source.Local().Record("sb2", "10.0.0.2") {
		t.Fatal("binding refused")
	}

	joining := New(time.Hour, 10)
	joining.now = source.now
	joining.Restore(source.Dump())

	if host, ok := joining.Local().Lookup("sb1"); !ok || host != "10.0.0.1" {
		t.Fatalf("the binding is %q, %v", host, ok)
	}
	if joining.Len() != 2 {
		t.Fatalf("the ledger holds %d live bindings", joining.Len())
	}
	now = now.Add(2 * time.Hour)
	if _, ok := joining.Local().Lookup("sb1"); ok {
		t.Fatal("an expired binding is still believed")
	}
	if len(joining.Dump()) != 2 {
		t.Fatal("an expired binding left the ledger without a command needing its room")
	}
}

// Restoring replaces what the ledger held: a replica installing a snapshot
// holds the cluster's bindings and none of its own.
func TestASnapshotReplacesTheLedgerItIsInstalledOn(t *testing.T) {
	ledger := New(time.Hour, 10)
	if !ledger.Local().Record("its-own", "10.0.0.1") {
		t.Fatal("binding refused")
	}
	ledger.Restore(nil)
	if _, ok := ledger.Local().Lookup("its-own"); ok {
		t.Fatal("the binding survived the snapshot")
	}
}
