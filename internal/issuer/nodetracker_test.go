package issuer

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestNodeTrackerEvictsOnlyBeyondRetention pins the 2*maxTTL eviction cutoff:
// an entry idle 3h with a 1h TTL goes, one idle 90m stays.
func TestNodeTrackerEvictsOnlyBeyondRetention(t *testing.T) {
	nt := NewNodeTracker(time.Hour)
	now := time.Now()
	nt.shard("stale").nodes["stale"] = nodeEntry{lastSeen: now.Add(-3 * time.Hour), certExpiry: now.Add(time.Hour)}
	nt.shard("fresh").nodes["fresh"] = nodeEntry{lastSeen: now.Add(-90 * time.Minute), certExpiry: now.Add(time.Hour)}

	nt.UpdateMetrics()

	if _, ok := nt.shard("stale").nodes["stale"]; ok {
		t.Error("entry idle beyond 2*maxTTL was not evicted")
	}
	if _, ok := nt.shard("fresh").nodes["fresh"]; !ok {
		t.Error("entry idle within 2*maxTTL was evicted")
	}
}

func TestNodeTrackerGauges(t *testing.T) {
	nt := NewNodeTracker(time.Hour)
	nt.Track("10.0.0.1", time.Now().Add(30*time.Minute))
	nt.UpdateMetrics()

	if got := testutil.ToFloat64(activeNodes); got != 1 {
		t.Fatalf("active nodes gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(oldestActiveCertExpiry); got < 1700 || got > 1801 {
		t.Fatalf("oldest cert expiry gauge = %v, want ~1800", got)
	}

	empty := NewNodeTracker(time.Hour)
	empty.UpdateMetrics()
	if got := testutil.ToFloat64(activeNodes); got != 0 {
		t.Fatalf("active nodes gauge = %v, want 0 for empty tracker", got)
	}
	if got := testutil.ToFloat64(oldestActiveCertExpiry); got != 0 {
		t.Fatalf("oldest cert expiry gauge = %v, want 0 for empty tracker", got)
	}
}

func TestNodeTrackerRunUpdaterStopsOnCancel(t *testing.T) {
	nt := NewNodeTracker(time.Hour)
	nt.Track("10.0.0.1", time.Now().Add(time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		nt.RunUpdater(ctx, time.Millisecond)
		close(done)
	}()
	// Let it tick at least once, then cancel.
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunUpdater did not return after cancel")
	}
}
