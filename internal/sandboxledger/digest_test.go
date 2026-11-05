package sandboxledger

import (
	"fmt"
	"testing"
	"time"
)

func TestTheBindingDigestIsTheBindingsAndNotTheOrder(t *testing.T) {
	clock := time.UnixMilli(1_000_000)
	first := New(time.Hour, 10)
	second := New(time.Hour, 10)
	ledgers := []*Ledger{first, second}
	for _, l := range ledgers {
		l.now = func() time.Time { return clock }
	}
	a := first.CommittedBy(&cluster{
		ledgers: ledgers,
		self:    0,
	})
	b := second.CommittedBy(&cluster{
		ledgers: ledgers,
		self:    1,
	})
	for i := range 6 {
		sandbox := fmt.Sprintf("sb%d", i)
		writer := a
		if i%2 == 1 {
			writer = b
		}
		if !writer.Record(sandbox, "10.0.0.1") {
			t.Fatalf("binding %s refused", sandbox)
		}
	}
	clock = clock.Add(30 * time.Minute)
	if !b.Record("sb3", "10.0.0.1") {
		t.Fatal("a refresh was refused")
	}

	want := first.Digest()
	if second.Digest() != want {
		t.Fatal("replicas that applied the same commands differ in their digests")
	}
	bindings := first.Dump()
	if DigestOf(bindings) != want {
		t.Fatal("the digest of the bindings differs from the digest the ledger keeps")
	}
	restored := New(time.Hour, 10)
	restored.Restore(bindings)
	if restored.Digest() != want {
		t.Fatal("a restored ledger differs from the ledger the snapshot came from")
	}
}

func TestTheBindingDigestNamesHostsAndExpiries(t *testing.T) {
	handle, ledger, clock := testLedger(t, time.Hour, 2)
	if !handle.Record("sb1", "10.0.0.1") {
		t.Fatal("binding refused")
	}
	bound := ledger.Digest()

	*clock = clock.Add(30 * time.Minute)
	if !handle.Record("sb1", "10.0.0.1") {
		t.Fatal("refresh refused")
	}
	if ledger.Digest() == bound {
		t.Fatal("a binding believed half an hour longer kept its digest")
	}

	// At the cap the expired binding goes.
	*clock = clock.Add(2 * time.Hour)
	if !handle.Record("sb2", "10.0.0.2") || !handle.Record("sb3", "10.0.0.3") {
		t.Fatal("bindings within the cap were refused")
	}
	if live := ledger.Len(); live != 2 {
		t.Fatalf("the ledger holds %d live bindings, want the 2 it took at the cap", live)
	}
	fresh, freshLedger, freshClock := testLedger(t, time.Hour, 2)
	*freshClock = *clock
	if !fresh.Record("sb2", "10.0.0.2") || !fresh.Record("sb3", "10.0.0.3") {
		t.Fatal("bindings within the cap were refused")
	}
	if ledger.Digest() != freshLedger.Digest() {
		t.Fatal("a dropped binding left a trace in the digest")
	}
}
