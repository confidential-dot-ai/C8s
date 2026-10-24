package cdsha

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// bigWorkload is a workload of about n containers (about 110 bytes each in
// the journaled document); seq makes each version distinct.
func bigWorkload(t *testing.T, seq, n int) pkgallowlist.Workload {
	t.Helper()
	cs := make([]pkgallowlist.Container, 0, n)
	for i := range n {
		d, err := types.ParseDigest(fmt.Sprintf("sha256:%08x%056x", seq, i))
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, pkgallowlist.Container{Digest: d})
	}
	return pkgallowlist.Workload{Containers: cs}
}

// The leader prunes a history over its byte bound within a Tick, not once
// per Timing.Backup: with large documents the history otherwise overshoots
// its bound by every document written in the interval (F6: about 113 MiB in
// a minute, past the admission cap). Pruning writes nothing while the
// cluster is idle, and at most one entry per Tick under load.
func TestLeaderPrunesTheHistoryWithinATick(t *testing.T) {
	tm := testTiming
	tm.Backup = time.Minute // the production interval: pruning must not wait for it
	c := newCluster(t, 3)
	c.timing = &tm
	doc := 2000 // containers: documents of about 200 KiB
	c.historyBytes = int64(4 * 110 * doc)
	c.historyVersions = 1000
	c.genesis("n0", "n1", "n2")
	budgetEntries := func() (have, fit int) {
		l := c.leader()
		if l == nil {
			return 0, 0
		}
		have, _ = l.al.HistoryLen()
		fit, _ = l.al.HistoryKeepForBytes(c.historyBytes)
		return have, fit
	}
	// put writes through whichever replica leads, again after a leader
	// change (the race detector slows large writes a lot).
	put := func(c *cluster, name string, w pkgallowlist.Workload) {
		t.Helper()
		for try := 0; ; try++ {
			l := c.leader()
			if l != nil {
				err := l.al.PutWorkload(name, w)
				if err == nil {
					return
				}
				if !errors.Is(err, allowlist.ErrUnavailable) || try > 100 {
					t.Fatal(err)
				}
			}
			time.Sleep(tm.Tick)
		}
	}
	prunes := func(c *cluster) (n int64) {
		for _, r := range c.live() {
			n += r.node.prunes.Load()
		}
		return n
	}
	// Large documents, one write per two Ticks: the history may pass its
	// bound by the writes of one Tick, no more.
	worst := 0
	for i := range 40 {
		put(c, "big", bigWorkload(t, i, doc))
		time.Sleep(2 * tm.Tick)
		have, fit := budgetEntries()
		worst = max(worst, have-fit)
	}
	have, fit := budgetEntries()
	t.Logf("large documents: worst %d entries over the byte bound; now %d entries, %d fit; %d prune entries for 40 writes", worst, have, fit, prunes(c))
	if worst > 2 {
		t.Fatalf("history overshot its byte bound by %d entries (prune waits for Timing.Backup)", worst)
	}
	// Idle: no prune entries.
	time.Sleep(4 * tm.Tick)
	idle := prunes(c)
	time.Sleep(40 * tm.Tick)
	if n := prunes(c) - idle; n != 0 {
		t.Fatalf("%d prune entries while idle", n)
	}
	// Steady small documents (the byte bound does not bind; the version
	// bound does, with its slack): prune entries stay far below one per
	// write and at most one per Tick.
	c2 := newCluster(t, 3)
	c2.timing = &tm
	c2.historyVersions = 10
	c2.historyBytes = 64 << 20
	c2.genesis("m0", "m1", "m2")
	start, before := time.Now(), prunes(c2)
	writes := 0
	for time.Since(start) < 60*tm.Tick {
		put(c2, fmt.Sprintf("s%d", writes%5), mkWorkload(t, writes))
		writes++
	}
	n := prunes(c2) - before
	el := time.Since(start)
	perTick := float64(n) * float64(tm.Tick) / float64(el)
	t.Logf("small documents: %d prune entries for %d writes in %s (%.2f per Tick: about %.0f per minute at the production 1 s Tick)", n, writes, el.Round(time.Millisecond), perTick, perTick*60)
	if n > int64(el/tm.Tick)+1 || (writes > 2*pruneSlack && n > int64(writes/pruneSlack)+2) {
		t.Fatalf("%d prune entries for %d writes in %s", n, writes, el)
	}
}
