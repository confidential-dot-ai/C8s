package allowlist

import (
	"fmt"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func pruneWorkload(t *testing.T, i int) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+1))
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: d}}}
}

// Pruning keeps the newest entries and the documents they name; the served
// document survives, and the bytes behind every kept entry still verify.
func TestPruneHistoryKeepsTheNewest(t *testing.T) {
	store := openJournaled(t)
	for i := range 10 {
		if err := store.PutWorkload(fmt.Sprintf("w%d", i), pruneWorkload(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := store.History()
	if len(before) != 11 { // the start document plus ten writes
		t.Fatalf("history %d", len(before))
	}
	if _, err := store.PruneHistory(0); err == nil {
		t.Fatal("keeping nothing accepted")
	}
	dropped, err := store.PruneHistory(4)
	if err != nil || dropped != 7 {
		t.Fatalf("dropped %d: %v", dropped, err)
	}
	after, _ := store.History()
	if len(after) != 4 || after[0].Position != before[7].Position || after[3].Digest != before[10].Digest {
		t.Fatalf("kept %+v", after)
	}
	for _, e := range after {
		if _, ok, err := store.Object(e.Digest); !ok || err != nil {
			t.Fatalf("kept entry %d lost its document: %v", e.Position, err)
		}
	}
	if _, ok, _ := store.Object(before[0].Digest); ok {
		t.Fatal("a pruned document is still served")
	}
	served, _ := servedDigest(t, store)
	if served != after[3].Digest {
		t.Fatal("the served document is not the head")
	}
	if n, _ := store.HistoryLen(); n != 4 {
		t.Fatalf("HistoryLen %d", n)
	}
	if dropped, err := store.PruneHistory(4); dropped != 0 || err != nil {
		t.Fatalf("second prune: %d %v", dropped, err)
	}
	// The journal still verifies at the next start.
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
}

// Through Apply (the replicated path) two replicas prune identically.
func TestPruneHistoryIsDeterministic(t *testing.T) {
	a, b := openJournaled(t), openJournaled(t)
	for i := range 6 {
		cmd := Command{Op: OpPutWorkload, Name: fmt.Sprintf("w%d", i), AtMS: int64(1000 + i)}
		w := pruneWorkload(t, i)
		cmd.Workload = &w
		for _, s := range []*Store{a, b} {
			if res := s.Apply(cmd); res.Err != "" {
				t.Fatal(res.Err)
			}
		}
	}
	for _, s := range []*Store{a, b} {
		if res := s.Apply(Command{Op: OpPruneHistory, Keep: 3}); res.Err != "" || res.Retired != 4 {
			t.Fatalf("%+v", res)
		}
	}
	ha, _ := a.History()
	hb, _ := b.History()
	if len(ha) != 3 || fmt.Sprint(ha) != fmt.Sprint(hb) {
		t.Fatalf("replicas differ:\n%v\n%v", ha, hb)
	}
}

// The byte budget counts each distinct document once, newest first, and
// always keeps the served one; pruning frees pages, which LiveBytes sees.
func TestHistoryKeepForBytesAndLiveBytes(t *testing.T) {
	store := openJournaled(t)
	for i := range 8 {
		if err := store.PutWorkload(fmt.Sprintf("w%d", i), pruneWorkload(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := store.History()
	last, _, _ := store.Object(h[len(h)-1].Digest)
	if keep, err := store.HistoryKeepForBytes(1); err != nil || keep != 1 {
		t.Fatalf("tiny budget keeps the head only: %d %v", keep, err)
	}
	if keep, _ := store.HistoryKeepForBytes(int64(len(last)) * 3); keep < 2 || keep >= len(h) {
		t.Fatalf("budget of ~3 documents kept %d of %d", keep, len(h))
	}
	if keep, _ := store.HistoryKeepForBytes(1 << 40); keep != len(h) {
		t.Fatalf("huge budget kept %d of %d", keep, len(h))
	}
	before, err := store.LiveBytes()
	if err != nil || before <= 0 {
		t.Fatalf("live bytes: %d %v", before, err)
	}
	if _, err := store.PruneHistory(1); err != nil {
		t.Fatal(err)
	}
	if after, _ := store.LiveBytes(); after >= before {
		t.Fatalf("pruning freed nothing: %d -> %d", before, after)
	}
}
