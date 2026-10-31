package allowlist

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func historyWorkload(t *testing.T, i int) pkgallowlist.Workload {
	t.Helper()
	digest, err := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+1))
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: digest}}}
}

// Pruning keeps the newest entries and the documents they name.
func TestPruneHistoryKeepsTheNewest(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	for i := range 10 {
		putEntry(t, allowlist, fmt.Sprintf("w%d", i), historyWorkload(t, i))
	}
	before, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 11 { // the start document plus ten writes
		t.Fatalf("history has %d entries, want 11", len(before))
	}
	if err := store.pruneHistory(0); err == nil {
		t.Fatal("a prune keeping nothing was applied")
	}
	if err := store.pruneHistory(4); err != nil {
		t.Fatal(err)
	}

	after, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
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
	if served, _ := servedDigest(t, allowlist); served != after[3].Digest {
		t.Fatal("the served document is not the head of the pruned history")
	}
	if n, _ := store.HistoryLen(); n != 4 {
		t.Fatalf("HistoryLen = %d, want 4", n)
	}
	if err := allowlist.StartJournal(); err != nil {
		t.Fatal(err)
	}
}

// Replicas pruning at the same command drop the same entries.
func TestPruneHistoryIsDeterministic(t *testing.T) {
	stores, st := replicated(t, 2)
	for i := range 6 {
		putEntry(t, st[i%2], fmt.Sprintf("w%d", i), historyWorkload(t, i))
	}
	prune := Command{
		Op:   OpPruneHistory,
		Keep: 3,
		AtMS: time.Now().UnixMilli(),
	}
	for i, s := range stores {
		if r := s.Apply(prune); r.Message != "" {
			t.Fatalf("replica %d: %+v", i, r)
		}
	}
	first, err := stores[0].History()
	if err != nil {
		t.Fatal(err)
	}
	second, err := stores[1].History()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || !reflect.DeepEqual(first, second) {
		t.Fatalf("replicas differ:\n%v\n%v", first, second)
	}
}

// The byte budget counts each distinct document once and always keeps the
// served one.
func TestHistoryKeepForBytesAndLiveBytes(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	for i := range 8 {
		putEntry(t, allowlist, fmt.Sprintf("w%d", i), historyWorkload(t, i))
	}
	history, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	head, _, err := store.Object(history[len(history)-1].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if keep, err := store.HistoryKeepForBytes(1); err != nil || keep != 1 {
		t.Fatalf("a budget under one document keeps %d, %v; want the head alone", keep, err)
	}
	if keep, _ := store.HistoryKeepForBytes(int64(len(head)) * 3); keep < 2 || keep >= len(history) {
		t.Fatalf("a budget of about three documents kept %d of %d", keep, len(history))
	}
	if keep, _ := store.HistoryKeepForBytes(1 << 40); keep != len(history) {
		t.Fatalf("a budget over the whole history kept %d of %d", keep, len(history))
	}

	before, err := store.LiveBytes()
	if err != nil || before <= 0 {
		t.Fatalf("LiveBytes = %d, %v", before, err)
	}
	if err := store.pruneHistory(1); err != nil {
		t.Fatal(err)
	}
	if after, _ := store.LiveBytes(); after >= before {
		t.Fatalf("pruning freed nothing: %d -> %d", before, after)
	}
}
