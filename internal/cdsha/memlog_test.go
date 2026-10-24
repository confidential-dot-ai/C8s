package cdsha

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// The byte count follows stores, overwrites of an index and deletes.
func TestMemLogCountsBytes(t *testing.T) {
	m := newMemLog()
	logs := []*raft.Log{{Index: 1, Data: make([]byte, 10)}, {Index: 2, Data: make([]byte, 20)}, {Index: 3, Data: make([]byte, 30), Extensions: make([]byte, 5)}}
	if err := m.StoreLogs(logs); err != nil {
		t.Fatal(err)
	}
	check := func(when string, entries uint64, bytes int64) {
		t.Helper()
		if e, b := m.usage(); e != entries || b != bytes {
			t.Fatalf("%s: %d entries %d bytes, want %d %d", when, e, b, entries, bytes)
		}
	}
	check("stored", 3, 65)
	if err := m.StoreLog(&raft.Log{Index: 3, Data: make([]byte, 7)}); err != nil {
		t.Fatal(err)
	}
	check("index 3 replaced", 3, 37)
	if err := m.DeleteRange(1, 2); err != nil {
		t.Fatal(err)
	}
	check("compacted", 1, 7)
	if err := m.DeleteRange(3, 3); err != nil {
		t.Fatal(err)
	}
	check("empty", 0, 0)
}

// A follower compacts its in-memory log on Raft's snapshot check, not only
// when a leader's backup does: its log stays near threshold + trailing
// entries under steady writes instead of growing until a 2-4 minute check.
func TestFollowerLogIsCompactedOnTheSnapshotInterval(t *testing.T) {
	saved := snapshotInterval
	snapshotInterval = 500 * time.Millisecond
	t.Cleanup(func() { snapshotInterval = saved })
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	for i := 0; i < 1200; {
		l := c.leader()
		if l == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := l.al.PutWorkload(fmt.Sprintf("w%d", i%50), mkWorkload(t, i)); err != nil {
			if errors.Is(err, allowlist.ErrUnavailable) {
				continue // a leader change under load: write again
			}
			t.Fatal(err)
		}
		i++
	}
	l := c.leader()
	// Two checks (each at 1-2x the interval) after the writes stop.
	time.Sleep(4 * snapshotInterval)
	for _, r := range c.live() {
		if r == l {
			continue
		}
		st := r.node.Status()
		t.Logf("%s: %d entries, %d bytes, snapshot at index %d", r.name, st.LogEntries, st.LogBytes, st.SnapshotIndex)
		if st.LogEntries > 512+256+64 || st.SnapshotIndex == 0 {
			t.Fatalf("follower %s log not compacted: %d entries, snapshot index %d", r.name, st.LogEntries, st.SnapshotIndex)
		}
	}
}
