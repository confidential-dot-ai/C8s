package cdsha

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// A forwarded binding applies at the leader's time, not at the time the
// forwarding replica's clock gave it: one replica with a clock far ahead
// cannot expire a live binding and bind the sandbox to another host.
func TestForwardedBindingAppliesAtTheLeadersTime(t *testing.T) {
	s := newSolo(t, nil)
	n := s.node
	pinned := Claims{Measurement: "m1"}
	forward := func(host string, at time.Time) string {
		t.Helper()
		raw, err := json.Marshal(Entry{Kind: KindBinding, Binding: bindingAt("sb", host, at.UnixMilli())})
		if err != nil {
			t.Fatal(err)
		}
		resp := n.handleControl(pinned, controlRequest{Op: ctlApply, Entry: raw})
		if resp.Err != "" {
			t.Fatalf("forward %s: %s", host, resp.Err)
		}
		return string(resp.Response)
	}
	if held := forward("A", time.Now()); held != "true" {
		t.Fatalf("first binding: %s", held)
	}
	if held := forward("B", time.Now().Add(48*time.Hour)); held != "false" {
		t.Fatalf("a binding stamped two days ahead took the sandbox: %s", held)
	}
	if h, ok := n.cfg.Ledger.Lookup("sb"); !ok || h != "A" {
		t.Fatalf("sb bound to %q (%v), want A", h, ok)
	}
	// An allowlist write is journaled at the leader's time too.
	w := mkWorkload(t, 1)
	raw, err := json.Marshal(Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: "w", Workload: &w, AtMS: time.Now().Add(48 * time.Hour).UnixMilli()}})
	if err != nil {
		t.Fatal(err)
	}
	if resp := n.handleControl(pinned, controlRequest{Op: ctlApply, Entry: raw}); resp.Err != "" {
		t.Fatalf("forward allowlist write: %s", resp.Err)
	}
	hist, err := n.cfg.Allowlist.History()
	if err != nil || len(hist) == 0 {
		t.Fatalf("history: %v, %d entries", err, len(hist))
	}
	if at := hist[len(hist)-1].PublishedAt; at.After(time.Now().Add(time.Hour)) {
		t.Fatalf("allowlist write journaled at the forwarder's time %s", at)
	}
}

// Time in the replicated state does not go backwards: a command stamped
// before one already applied (a new leader whose clock is behind the old
// one's) applies at the later time, on every replica alike.
func TestBindingTimeNeverGoesBackwards(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub) // ledger ttl: one hour
	t0 := time.Now().Add(-40 * time.Minute)
	ms := func(d time.Duration) int64 { return t0.Add(d).UnixMilli() }
	if res := applyAt(f, 1, Entry{Kind: KindBinding, Binding: bindingAt("sb", "A", ms(0))}); res != true {
		t.Fatalf("A: %v", res)
	}
	// A refresh from a clock 50 minutes behind would shorten A's binding to
	// end ten minutes after t0.
	if res := applyAt(f, 2, Entry{Kind: KindBinding, Binding: bindingAt("sb", "A", ms(-50*time.Minute))}); res != true {
		t.Fatalf("A refresh: %v", res)
	}
	if res := applyAt(f, 3, Entry{Kind: KindBinding, Binding: bindingAt("sb", "B", ms(30*time.Minute))}); res != false {
		t.Fatalf("B took the sandbox while A's binding was live: %v", res)
	}
	if h, ok := f.ledger.Lookup("sb"); !ok || h != "A" {
		t.Fatalf("sb bound to %q (%v), want A", h, ok)
	}
	// A replica that joins from a snapshot keeps the time.
	g := newTestFSM(t, opPub)
	if err := restoreCopy(t, f, g); err != nil {
		t.Fatal(err)
	}
	if got, want := g.Core().ClockMS, f.Core().ClockMS; got != want || want != ms(30*time.Minute) {
		t.Fatalf("restored clock %d, applied %d, want %d", got, want, ms(30*time.Minute))
	}
}
