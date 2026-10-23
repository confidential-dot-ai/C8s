package sandboxledger

import (
	"encoding/json"
	"testing"
	"time"
)

// SnapshotBytes is a running total kept through records, refreshes,
// evictions and restores, and bounds the bindings' JSON in a snapshot.
func TestSnapshotBytesIsARunningTotal(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(time.Minute, 3)
	l.now = func() time.Time { return now }
	check := func(when string) {
		t.Helper()
		var sum int64
		dump := l.Dump()
		for _, b := range dump {
			sum += bindingBytes(b.SandboxID, b.Host)
		}
		j, _ := json.Marshal(dump)
		if got := l.SnapshotBytes(); got != sum || got+2 < int64(len(j)) { // +2: the array's brackets
			t.Fatalf("%s: SnapshotBytes %d, sum %d, JSON %d", when, got, sum, len(j))
		}
	}
	check("empty")
	l.recordAt(now, "s1", "host-a")
	l.recordAt(now, "s2", "host-b")
	check("records")
	l.recordAt(now, "s1", "host-a")
	check("refresh")
	now = now.Add(2 * time.Minute)
	l.recordAt(now, "s1", "a-longer-host-name")
	check("expired binding rebound")
	l.recordAt(now, "s3", "h")
	l.recordAt(now, "s4", "h") // full: evicts s2
	check("eviction")
	r := New(time.Minute, 3)
	r.Restore(l.Dump())
	if r.SnapshotBytes() != l.SnapshotBytes() {
		t.Fatalf("restored %d, source %d", r.SnapshotBytes(), l.SnapshotBytes())
	}
	l.Restore(nil)
	check("restored empty")
}
