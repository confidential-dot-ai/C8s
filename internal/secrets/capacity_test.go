package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var errCapacity = fmt.Errorf("%w: %w", ErrCapacity, errors.New("cds-ha: the replicated state is at its snapshot capacity: ..."))

type capacityRepl struct{}

func (capacityRepl) ReplicateSecret(Command) (Result, error) { return Result{}, errCapacity }

// A write the HA admission cap refuses is 507 with the retryable
// state_capacity code: not 503 (the cluster is up), not 500, and not
// secret_store_full, which get-secret treats as terminal.
func TestCapacityRefusalIs507(t *testing.T) {
	t.Run("workload create", func(t *testing.T) {
		hn := newHarness(t)
		hn.h.Store = failingStore{err: errCapacity}
		w := do(hn.h, hn.request(t, http.MethodPost, "/api/db"))
		if w.Code != http.StatusInsufficientStorage || !strings.Contains(w.Body.String(), types.ErrorCodeStateCapacity) {
			t.Fatalf("POST = %d %s, want 507 %s", w.Code, w.Body, types.ErrorCodeStateCapacity)
		}
	})
	t.Run("operator put", func(t *testing.T) {
		oh := newOperatorHarness(t)
		oh.h.Store = ReplicatedStore{MemoryStore: oh.store, Repl: capacityRepl{}}
		for _, overwrite := range []bool{false, true} {
			w, _ := doPut(oh.h, putRequest(t, "/tenant-a/db", []byte("v"), overwrite))
			if w.Code != http.StatusInsufficientStorage || !strings.Contains(w.Body.String(), types.ErrorCodeStateCapacity) {
				t.Errorf("overwrite=%v: %d %s, want 507 %s", overwrite, w.Code, w.Body, types.ErrorCodeStateCapacity)
			}
		}
	})
}

// SnapshotBytes is a running total: after puts, overwrites by another
// holder and a restore it equals the sum over the entries, and bounds their
// JSON in a snapshot.
func TestSnapshotBytesIsARunningTotal(t *testing.T) {
	s := NewMemoryStore(16, 8, 64)
	ctx := context.Background()
	check := func(when string) {
		t.Helper()
		var sum int64
		dump := s.Dump()
		for _, e := range dump {
			sum += entryBytes(e.Path, e.Value, Holder{origin: e.Origin, name: e.Name})
		}
		j, _ := json.Marshal(dump)
		if got := s.SnapshotBytes(); got != sum || got+2 < int64(len(j)) { // +2: the array's brackets
			t.Fatalf("%s: SnapshotBytes %d, sum %d, JSON %d", when, got, sum, len(j))
		}
	}
	check("empty")
	if _, _, err := s.PutIfAbsent(ctx, "/a", []byte("value-a"), WorkloadHolder("w")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "/b", []byte("\x00\"<>\\")); err != nil {
		t.Fatal(err)
	}
	check("puts")
	if _, err := s.Put(ctx, "/a", []byte("a much longer replacement value")); err != nil {
		t.Fatal(err)
	}
	check("overwrite by the operator")
	if _, err := s.Put(ctx, "/a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	check("shrinking overwrite")
	if g := s.SnapshotGrowth(Command{Op: OpPut, Path: "/a", Value: []byte("y")}); g != 0 {
		t.Fatalf("same-size overwrite grows by %d", g)
	}
	if g := s.SnapshotGrowth(Command{Op: OpPutIfAbsent, Path: "/a", Value: []byte("longer"), Origin: OriginWorkload, Name: "w"}); g != 0 {
		t.Fatalf("put_if_absent on a held path grows by %d", g)
	}
	if g := s.SnapshotGrowth(Command{Op: OpPut, Path: "/new", Value: []byte("v")}); g <= 0 {
		t.Fatalf("a new path grows by %d", g)
	}
	r := NewMemoryStore(16, 8, 64)
	r.Restore(s.Dump())
	if r.SnapshotBytes() != s.SnapshotBytes() {
		t.Fatalf("restored %d, source %d", r.SnapshotBytes(), s.SnapshotBytes())
	}
	s.Restore(nil)
	check("restored empty")
}
