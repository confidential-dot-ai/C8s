package cdsha

import (
	"testing"
	"time"
)

// One command stamped by a leader clock set far ahead affects only that
// command. Once the clock is back, a live binding made before stays live,
// and bindings made after expire after their TTL, so the ledger empties.
func TestClockExcursionEndsWithTheExcursion(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub) // ledger: ttl 1h, max 8
	now := time.Now()
	if res := applyAt(f, 1, Entry{Kind: KindBinding, Binding: bindingAt("live", "A", now.UnixMilli())}); res != true {
		t.Fatalf("A: %v", res)
	}
	// One write while the leader's clock is 30 days ahead.
	if res := applyAt(f, 2, Entry{Kind: KindBinding, Binding: bindingAt("other", "X", now.Add(30*24*time.Hour).UnixMilli())}); res != true {
		t.Fatalf("excursion write: %v", res)
	}
	// The clock is back; a minute later another host asks for "live".
	res := applyAt(f, 3, Entry{Kind: KindBinding, Binding: bindingAt("live", "B", now.Add(time.Minute).UnixMilli())})
	if h, _ := f.ledger.Lookup("live"); res == true || h != "A" {
		t.Errorf("host B took the live sandbox bound to A a minute ago after the clock came back (res=%v, bound to %q)", res, h)
	}
	for i := 0; i < 8; i++ {
		applyAt(f, uint64(10+i), Entry{Kind: KindBinding, Binding: bindingAt(string(rune('a'+i)), "H", now.Add(2*time.Minute).UnixMilli())})
	}
	later := now.Add(2 * time.Hour) // every binding made after the excursion has expired
	if res := applyAt(f, 30, Entry{Kind: KindBinding, Binding: bindingAt("new", "H", later.UnixMilli())}); res != true {
		t.Errorf("two hours later (TTL 1h) a new binding is refused: the ledger still holds bindings the excursion stamped")
	}
}
