package sandboxledger

import (
	"testing"
	"time"
)

// testLedger is a handle, the ledger it writes to, and a clock the test moves.
func testLedger(t *testing.T, ttl time.Duration, max int) (*Handle, *Ledger, *time.Time) {
	t.Helper()
	clock := time.Unix(1_700_000_000, 0)
	l := New(ttl, max)
	l.now = func() time.Time { return clock }
	return l.Local(), l, &clock
}

func TestRecordFirstWriteWins(t *testing.T) {
	l, _, _ := testLedger(t, time.Hour, 10)

	if !l.Record("sandbox-1", "10.0.0.1") {
		t.Fatal("first binding refused")
	}
	if l.Record("sandbox-1", "10.0.0.2") {
		t.Fatal("a second inventory claimed a bound sandbox")
	}
	host, ok := l.Lookup("sandbox-1")
	if !ok || host != "10.0.0.1" {
		t.Fatalf("lookup = %q %v, want the original host", host, ok)
	}
}

// A workload renews on an interval and re-presents the same pair, so the same
// host re-recording must refresh rather than conflict.
func TestRecordSameHostRefreshes(t *testing.T) {
	l, _, clock := testLedger(t, time.Hour, 10)
	l.Record("sandbox-1", "10.0.0.1")

	*clock = clock.Add(50 * time.Minute)
	if !l.Record("sandbox-1", "10.0.0.1") {
		t.Fatal("the bound host was refused its own refresh")
	}

	// The refresh extended the binding past the original expiry.
	*clock = clock.Add(30 * time.Minute)
	if _, ok := l.Lookup("sandbox-1"); !ok {
		t.Fatal("binding expired despite being refreshed")
	}
}

func TestExpiredBindingIsReclaimable(t *testing.T) {
	l, _, clock := testLedger(t, time.Hour, 10)
	l.Record("sandbox-1", "10.0.0.1")

	*clock = clock.Add(time.Hour + time.Second)
	if _, ok := l.Lookup("sandbox-1"); ok {
		t.Fatal("expired binding still resolved")
	}
	if !l.Record("sandbox-1", "10.0.0.2") {
		t.Fatal("an expired binding blocked a new host")
	}
}

func TestLookupUnknown(t *testing.T) {
	l, _, _ := testLedger(t, time.Hour, 10)
	if _, ok := l.Lookup("nope"); ok {
		t.Fatal("unknown sandbox resolved")
	}
}

func TestRecordRejectsEmpty(t *testing.T) {
	l, _, _ := testLedger(t, time.Hour, 10)
	if l.Record("", "10.0.0.1") || l.Record("sandbox-1", "") {
		t.Fatal("an empty sandbox or host was bound")
	}
}

// The cap bounds a rogue inventory minting tokens for fabricated sandbox IDs.
// Expired entries are reclaimed first, so ordinary churn does not hit it.
func TestCapBoundsGrowth(t *testing.T) {
	l, _, clock := testLedger(t, time.Hour, 2)
	if !l.Record("a", "10.0.0.1") || !l.Record("b", "10.0.0.1") {
		t.Fatal("bindings within the cap were refused")
	}
	if l.Record("c", "10.0.0.1") {
		t.Fatal("the cap did not bound growth")
	}
	// An existing binding still refreshes at the cap.
	if !l.Record("a", "10.0.0.1") {
		t.Fatal("refresh refused at the cap")
	}

	*clock = clock.Add(time.Hour + time.Second)
	if !l.Record("c", "10.0.0.1") {
		t.Fatal("expired entries were not reclaimed to make room")
	}
}

func TestLenCountsLiveBindings(t *testing.T) {
	h, l, clock := testLedger(t, time.Hour, 10)
	h.Record("a", "10.0.0.1")
	h.Record("b", "10.0.0.1")
	if got := l.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	*clock = clock.Add(time.Hour + time.Second)
	if got := l.Len(); got != 0 {
		t.Fatalf("Len after expiry = %d, want 0", got)
	}
}
