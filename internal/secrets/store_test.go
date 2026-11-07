package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// holderTotal returns the sum of the per-holder counts and the number of paths,
// which the store must keep equal.
func holderTotal(s *MemoryStore) (total, paths int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.holders {
		total += n
	}
	return total, len(s.values)
}

func TestMemoryStoreGetMissing(t *testing.T) {
	s := NewMemoryStore(10, 9, 64)
	if _, err := s.Get(context.Background(), "/nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// The first writer defines the value; a later one is told what is there and
// that it did not create it — which is how a losing replica recovers.
func TestMemoryStorePutIfAbsent(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10, 9, 64)

	got, held, err := s.PutIfAbsent(ctx, "/a", []byte("first"), WorkloadHolder("api"))
	if err != nil || held.Exists || !bytes.Equal(got, []byte("first")) {
		t.Fatalf("first put: %q %+v %v", got, held, err)
	}
	got, held, err = s.PutIfAbsent(ctx, "/a", []byte("second"), OperatorHolder())
	if err != nil {
		t.Fatal(err)
	}
	if !held.Exists {
		t.Fatal("second put reported that it created the value")
	}
	if held.Origin != OriginWorkload {
		t.Fatalf("held origin = %q, want the first writer's", held.Origin)
	}
	if !bytes.Equal(got, []byte("first")) {
		t.Fatalf("second put = %q, want the original value", got)
	}
}

// Put replaces whatever is there and reports what that was, which is the only
// thing the operator write path learns about a value it did not write.
func TestMemoryStorePut(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10, 9, 64)

	held, err := s.Put(ctx, "/a", []byte("operator"))
	if err != nil || held.Exists {
		t.Fatalf("put onto an empty path: %+v %v", held, err)
	}

	if _, _, err := s.PutIfAbsent(ctx, "/b", []byte("generated"), WorkloadHolder("api")); err != nil {
		t.Fatal(err)
	}
	held, err = s.Put(ctx, "/b", []byte("operator"))
	if err != nil {
		t.Fatal(err)
	}
	if !held.Exists || held.Origin != OriginWorkload {
		t.Fatalf("held = %+v, want the displaced workload value", held)
	}
	got, err := s.Get(ctx, "/b")
	if err != nil || !bytes.Equal(got, []byte("operator")) {
		t.Fatalf("after replace: %q %v", got, err)
	}

	// The replacement carries its own origin forward.
	held, err = s.Put(ctx, "/b", []byte("again"))
	if err != nil || held.Origin != OriginOperator {
		t.Fatalf("held = %+v %v, want the operator value it replaced", held, err)
	}
}

// Put is bounded by the ceiling and the value cap, and replacing a path
// consumes no room.
func TestMemoryStorePutBounds(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(2, 1, 4)

	if _, err := s.Put(ctx, "/a", []byte("toolong")); err == nil {
		t.Fatal("an oversized value was stored")
	}
	for _, p := range []string{"/a", "/b"} {
		if _, err := s.Put(ctx, p, []byte("ok")); err != nil {
			t.Fatalf("put %s: %v", p, err)
		}
	}
	if _, err := s.Put(ctx, "/c", []byte("ok")); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("put at the ceiling = %v, want ErrStoreFull", err)
	}
	if _, err := s.Put(ctx, "/a", []byte("new")); err != nil {
		t.Fatalf("replacing an existing path at the ceiling: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
}

// A caller must not be able to reach into stored state through a returned
// slice.
func TestMemoryStoreCopiesValues(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10, 9, 64)
	original := []byte("secret")
	if _, _, err := s.PutIfAbsent(ctx, "/a", original, WorkloadHolder("api")); err != nil {
		t.Fatal(err)
	}
	original[0] = 'X' // mutate the caller's slice after storing

	got, err := s.Get(ctx, "/a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("stored value = %q, want it unaffected by the caller's slice", got)
	}
	got[0] = 'Y' // mutate what Get handed back
	again, _ := s.Get(ctx, "/a")
	if !bytes.Equal(again, []byte("secret")) {
		t.Fatalf("stored value = %q, want it unaffected by a mutated result", again)
	}
}

// One path each, so the ceiling is the bound the third write meets.
func TestMemoryStoreBounds(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(2, 1, 4)

	if _, _, err := s.PutIfAbsent(ctx, "/big", []byte("toolong"), WorkloadHolder("api")); err == nil {
		t.Fatal("an oversized value was stored")
	}
	for _, w := range []struct{ holder, path string }{{"a", "/one"}, {"b", "/two"}} {
		if _, _, err := s.PutIfAbsent(ctx, w.path, []byte("ok"), WorkloadHolder(w.holder)); err != nil {
			t.Fatalf("put %s: %v", w.path, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/three", []byte("ok"), WorkloadHolder("c")); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("put at the path cap = %v, want ErrStoreFull", err)
	}
	// An existing path still resolves at the cap.
	if _, held, err := s.PutIfAbsent(ctx, "/one", []byte("ok"), WorkloadHolder("a")); err != nil || !held.Exists {
		t.Fatalf("existing path at the cap: held=%+v err=%v", held, err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
}

// A holder meets its own quota while the ceiling is still far away.
func TestMemoryStoreHolderQuota(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(64, 2, 8)

	flooder := WorkloadHolder("flooder")
	stored := map[string]string{"/f/1": "one", "/f/2": "two"}
	for p, v := range stored {
		if _, _, err := s.PutIfAbsent(ctx, p, []byte(v), flooder); err != nil {
			t.Fatalf("put %s: %v", p, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/f/3", []byte("ok"), flooder); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("put past the quota = %v, want ErrHolderQuota", err)
	}
	// The quota refuses and keeps what it has, like the ceiling: a stored value
	// is the only copy.
	for p, v := range stored {
		got, err := s.Get(ctx, p)
		if err != nil || !bytes.Equal(got, []byte(v)) {
			t.Fatalf("%s = %q %v, want %q still stored", p, got, err, v)
		}
	}
	if s.Len() != len(stored) {
		t.Fatalf("Len = %d, want %d unchanged by a refusal", s.Len(), len(stored))
	}
	// An existing path still resolves for a holder at its quota: it grows
	// nothing.
	if _, held, err := s.PutIfAbsent(ctx, "/f/1", []byte("ok"), flooder); err != nil || !held.Exists {
		t.Fatalf("existing path at the quota: held=%+v err=%v", held, err)
	}
}

// A holder that floods is refused by the bound on itself; every other holder
// keeps writing.
func TestFloodingHolderDoesNotRefuseAnother(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(8, 2, 8)

	flooder, honest := WorkloadHolder("flooder"), WorkloadHolder("honest")
	stored, refused := 0, 0
	for i := range 100 {
		_, _, err := s.PutIfAbsent(ctx, fmt.Sprintf("/f/%d", i), []byte("ok"), flooder)
		switch {
		case err == nil:
			stored++
		case errors.Is(err, ErrHolderQuota):
			refused++
		default:
			t.Fatalf("flood write %d = %v, want its own quota to refuse it", i, err)
		}
	}
	if stored != 2 || refused != 98 {
		t.Fatalf("flood stored %d and was refused %d times, want 2 and 98", stored, refused)
	}

	for _, p := range []string{"/h/1", "/h/2"} {
		if _, _, err := s.PutIfAbsent(ctx, p, []byte("ok"), honest); err != nil {
			t.Fatalf("honest holder refused after the flood: %v", err)
		}
	}
	if total, paths := holderTotal(s); total != paths || paths != 4 {
		t.Fatalf("holder counts sum to %d over %d paths, want both 4", total, paths)
	}
}

func TestDefaultMaxPathsPerHolder(t *testing.T) {
	ctx := context.Background()
	if DefaultMaxPathsPerHolder != 64 {
		t.Fatalf("the shipped quota is %d, want 64", DefaultMaxPathsPerHolder)
	}
	s := NewMemoryStore(1024, DefaultMaxPathsPerHolder, 8)
	api := WorkloadHolder("api")

	for i := range DefaultMaxPathsPerHolder {
		if _, _, err := s.PutIfAbsent(ctx, fmt.Sprintf("/api/%d", i), []byte("ok"), api); err != nil {
			t.Fatalf("write %d under the default quota: %v", i+1, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/api/last", []byte("ok"), api); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("write %d under the default quota = %v, want ErrHolderQuota", DefaultMaxPathsPerHolder+1, err)
	}
}

func TestNewMemoryStoreRejectsAQuotaAboveTheCeiling(t *testing.T) {
	for _, tc := range []struct {
		name            string
		maxPaths, quota int
		wantPanic       bool
	}{
		{"at the ceiling", 2, 2, true},
		{"above the ceiling", 2, 3, true},
		{"one below the ceiling", 2, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if recovered := r != nil; recovered != tc.wantPanic {
					t.Fatalf("NewMemoryStore(%d, %d, 8) panicked=%v, want %v", tc.maxPaths, tc.quota, recovered, tc.wantPanic)
				}
				if want := fmt.Sprintf("maxPerHolder %d must be below maxPaths %d", tc.quota, tc.maxPaths); tc.wantPanic &&
					!strings.Contains(fmt.Sprint(r), want) {
					t.Fatalf("panic = %v, want it to name both bounds: %s", r, want)
				}
			}()
			NewMemoryStore(tc.maxPaths, tc.quota, 8)
		})
	}
}

// With both bounds exceeded at once the holder's quota is the one that answers.
// The collision needs a third holder: at a legal quota one holder cannot reach
// the ceiling alone.
func TestHolderQuotaAnswersBeforeTheCeiling(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(3, 2, 8)
	api, web := WorkloadHolder("api"), WorkloadHolder("web")

	for _, p := range []string{"/api/1", "/api/2"} {
		if _, _, err := s.PutIfAbsent(ctx, p, []byte("ok"), api); err != nil {
			t.Fatalf("put %s: %v", p, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/web/1", []byte("ok"), web); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want the ceiling reached as well as api's quota", s.Len())
	}
	if _, _, err := s.PutIfAbsent(ctx, "/api/3", []byte("ok"), api); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("both bounds exceeded = %v, want ErrHolderQuota", err)
	}
}

// The key is (origin, name), so an entry named "operator" holds its own bucket.
func TestWorkloadNamedOperatorIsNotTheOperator(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(8, 1, 8)

	if _, _, err := s.PutIfAbsent(ctx, "/op/1", []byte("ok"), OperatorHolder()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutIfAbsent(ctx, "/w/1", []byte("ok"), WorkloadHolder("operator")); err != nil {
		t.Fatalf("an entry named operator was charged the operator's paths: %v", err)
	}
	if _, _, err := s.PutIfAbsent(ctx, "/w/2", []byte("ok"), WorkloadHolder("operator")); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("an entry named operator escaped the quota: %v", err)
	}
}

// Only an explicit operator holder is exempt, so a Holder no constructor
// produced is still bounded.
func TestZeroHolderIsQuotaed(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(8, 1, 8)

	if _, _, err := s.PutIfAbsent(ctx, "/a", []byte("ok"), Holder{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutIfAbsent(ctx, "/b", []byte("ok"), Holder{}); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("second write from a zero holder = %v, want ErrHolderQuota", err)
	}
}

// The ceiling refuses and keeps what it has: a stored value is the only copy.
func TestMemoryStoreCeilingRefusesWithoutEvicting(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(2, 1, 8)

	stored := map[string]string{"/one": "a-value", "/two": "b-value"}
	for _, w := range []struct{ holder, path string }{{"a", "/one"}, {"b", "/two"}} {
		if _, _, err := s.PutIfAbsent(ctx, w.path, []byte(stored[w.path]), WorkloadHolder(w.holder)); err != nil {
			t.Fatalf("put %s: %v", w.path, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/three", []byte("c-value"), WorkloadHolder("c")); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("put at the ceiling = %v, want ErrStoreFull", err)
	}
	for p, v := range stored {
		got, err := s.Get(ctx, p)
		if err != nil || !bytes.Equal(got, []byte(v)) {
			t.Fatalf("%s = %q %v, want %q still stored", p, got, err, v)
		}
	}
}

// The quota bounds one holder, not the store: enough holders one path apiece
// still reach the ceiling, and the holder that arrives after them is refused.
func TestManyHoldersStillReachTheCeiling(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(8, 2, 8)

	for i := range 8 {
		p := fmt.Sprintf("/w%d/1", i)
		if _, _, err := s.PutIfAbsent(ctx, p, []byte("ok"), WorkloadHolder(fmt.Sprintf("w%d", i))); err != nil {
			t.Fatalf("holder %d's only path: %v", i, err)
		}
	}
	late := WorkloadHolder("late")
	if _, _, err := s.PutIfAbsent(ctx, "/late/1", []byte("ok"), late); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("a holder arriving at the full store = %v, want ErrStoreFull", err)
	}
	// It is the ceiling, not its own quota, that refuses it.
	if total, paths := holderTotal(s); total != paths || paths != 8 {
		t.Fatalf("holder counts sum to %d over %d paths, want both 8", total, paths)
	}
}

// Operator writes count against the ceiling only.
func TestOperatorWritesAreNotQuotaed(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(8, 1, 8)

	for i := range 4 {
		if _, _, err := s.PutIfAbsent(ctx, fmt.Sprintf("/op/%d", i), []byte("ok"), OperatorHolder()); err != nil {
			t.Fatalf("operator write %d: %v", i, err)
		}
	}
}

// Replacing a value moves the path's charge, so an operator taking over a
// workload's path returns that workload a unit of quota.
func TestReplacingAValueMovesItsCharge(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(8, 1, 16)
	api := WorkloadHolder("api")

	if _, _, err := s.PutIfAbsent(ctx, "/api/db", []byte("generated"), api); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutIfAbsent(ctx, "/api/hf", []byte("generated"), api); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("second path at a quota of 1 = %v, want ErrHolderQuota", err)
	}
	if _, err := s.Put(ctx, "/api/db", []byte("operator")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutIfAbsent(ctx, "/api/hf", []byte("generated"), api); err != nil {
		t.Fatalf("after the operator took the path over: %v", err)
	}
	if total, paths := holderTotal(s); total != paths || paths != 2 {
		t.Fatalf("holder counts sum to %d over %d paths, want both 2", total, paths)
	}
}

// Concurrent writers are each bounded exactly, and the counts stay consistent
// with the map.
func TestMemoryStoreQuotaUnderConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(64, 4, 8)

	names := []string{"a", "b"}
	stored := make([]atomic.Int64, len(names))
	var wg sync.WaitGroup
	for h, name := range names {
		by := WorkloadHolder(name)
		for i := range 32 {
			wg.Go(func() {
				if _, _, err := s.PutIfAbsent(ctx, fmt.Sprintf("/%s/%d", name, i), []byte("ok"), by); err == nil {
					stored[h].Add(1)
				}
			})
		}
	}
	// The census is taken under the same lock the writers hold, so -race sees
	// both sides.
	for range 8 {
		wg.Go(func() {
			s.TopHolders(censusHolders)
		})
	}
	wg.Wait()

	for h, name := range names {
		if got := stored[h].Load(); got != 4 {
			t.Fatalf("holder %s stored %d paths, want its quota of 4", name, got)
		}
	}
	if total, paths := holderTotal(s); total != paths || paths != 8 {
		t.Fatalf("holder counts sum to %d over %d paths, want both 8", total, paths)
	}
}

// The census names the holders and their counts, largest first. Four holders
// tied at one path pin the tie-break: without it the order is the map's.
func TestTopHolders(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(16, 4, 16)

	for i := range 2 {
		if _, _, err := s.PutIfAbsent(ctx, fmt.Sprintf("/api/%d", i), []byte("api-value"), WorkloadHolder("api")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"b", "c", "d"} {
		if _, _, err := s.PutIfAbsent(ctx, "/"+name+"/1", []byte("value"), WorkloadHolder(name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Put(ctx, "/op/1", []byte("op-value")); err != nil {
		t.Fatal(err)
	}

	want := []HolderPaths{
		{Holder: WorkloadHolder("api"), Paths: 2},
		{Holder: OperatorHolder(), Paths: 1},
		{Holder: WorkloadHolder("b"), Paths: 1},
		{Holder: WorkloadHolder("c"), Paths: 1},
		{Holder: WorkloadHolder("d"), Paths: 1},
	}
	if got := s.TopHolders(10); !slices.Equal(got, want) {
		t.Fatalf("TopHolders(10) = %+v, want %+v", got, want)
	}
	if got := s.TopHolders(2); !slices.Equal(got, want[:2]) {
		t.Fatalf("TopHolders(2) = %+v, want the first two of %+v", got, want)
	}
}

// Holder.String is what the census prints, and the operator has no name to
// print.
func TestHolderString(t *testing.T) {
	if got := OperatorHolder().String(); got != "operator" {
		t.Fatalf("operator holder = %q, want %q", got, "operator")
	}
	if got := WorkloadHolder("api").String(); got != `workload "api"` {
		t.Fatalf("workload holder = %q, want %q", got, `workload "api"`)
	}
}

func TestGenerate(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Fatalf("len = %d, want 32", len(a))
	}
	b, _ := Generate()
	if bytes.Equal(a, b) {
		t.Fatal("two generated values were identical")
	}
}
