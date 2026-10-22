package cdsha

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// The decree record is agreed state from format 2 on: a fresh cluster of this
// release raises the format once its seats fill and records every decree
// after; replicas agree on it, and a joiner takes it with the snapshot.
func TestDecreeRecordIsReplicated(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	eventually(t, 10*time.Second, "format 2", func() bool { return c.leader() != nil && c.leader().node.Core().format() >= 2 })
	for i, voters := range []int{5, 3} {
		d := c.decree(Decree{Kind: SetVoters, BaseEpoch: uint64(1 + i), Voters: voters})
		eventually(t, 10*time.Second, "decree applied", func() bool { st, ok := c.decrees.get(d); return ok && st.AppliedEpoch != nil })
	}
	for _, r := range c.live() {
		eventually(t, 5*time.Second, "record on "+r.name, func() bool {
			rec := r.node.Decrees()
			return len(rec) == 2 && rec[0].Epoch == 2 && rec[1].Epoch == 3 && rec[1].Decree.Decree.Voters == 3
		})
	}
	j := c.start("n3", "m1")
	eventually(t, 15*time.Second, "joiner has the record", func() bool { return len(j.node.Decrees()) == 2 })
}

// At format 1 (a group still running the previous release) nothing is
// recorded, so old and new replicas hold the same state; the record is
// bounded, oldest first out; and snapshots carry it.
func TestDecreeRecordFormatAndBound(t *testing.T) {
	_, opPub := operatorKey(t)
	al, sec, led := testStores(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	f.mu.Lock()
	f.record(SignedDecree{Decree: Decree{IntentID: "old"}}, 1, 1)
	f.mu.Unlock()
	if len(f.Decrees()) != 0 {
		t.Fatal("recorded at format 1")
	}
	f.mu.Lock()
	f.core.Format = 2
	for i := range maxDecreeRecord + 10 {
		f.record(SignedDecree{Decree: Decree{IntentID: "d"}}, int64(i), uint64(i))
	}
	f.mu.Unlock()
	rec := f.Decrees()
	if len(rec) != maxDecreeRecord || rec[0].Epoch != 10 {
		t.Fatalf("bound: %d records, first epoch %d", len(rec), rec[0].Epoch)
	}
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	al2, sec2, led2 := testStores(t)
	g := NewFSM(PreGenesis(testCluster, opPub), al2, sec2, led2)
	if err := g.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err != nil || len(g.Decrees()) != maxDecreeRecord {
		t.Fatalf("restore: %v, %d records", err, len(g.Decrees()))
	}
}
