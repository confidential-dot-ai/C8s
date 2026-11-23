package ta

import (
	"sync"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// countingStore is a fakeStore that counts LoadAll calls and carries a
// mutation generation the way internal/allowlist.Store does.
type countingStore struct {
	mu    sync.Mutex
	inner fakeStore
	loads int
	gen   uint64
}

func (s *countingStore) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	s.mu.Lock()
	s.loads++
	s.mu.Unlock()
	return s.inner.LoadAll()
}

func (s *countingStore) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

// write models an allowlist mutation: the document changes and the generation
// moves.
func (s *countingStore) write(inner fakeStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inner = inner
	s.gen++
}

func (s *countingStore) loadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads
}

func TestPolicySnapshotCacheReusesUntilWritten(t *testing.T) {
	store := &countingStore{inner: completeAPIStore(t)}
	cache := &policySnapshotCache{}

	first, err := cache.snapshot(store)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		got, err := cache.snapshot(store)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatal("cache returned a different snapshot without a write")
		}
	}
	if n := store.loadCount(); n != 1 {
		t.Fatalf("LoadAll called %d times across 21 requests, want 1", n)
	}

	// A write must be picked up on the very next request, not eventually.
	store.write(fakeStore{workloads: map[string]pkgallowlist.Workload{"renamed": namedEntry(t, wlDigestA)}})
	after, err := cache.snapshot(store)
	if err != nil {
		t.Fatal(err)
	}
	if after == first {
		t.Fatal("cache served the pre-write snapshot")
	}
	if _, ok := after.Allowlist.Workloads["renamed"]; !ok {
		t.Fatalf("reloaded snapshot does not carry the write: %+v", after.Allowlist.Workloads)
	}
	if n := store.loadCount(); n != 2 {
		t.Fatalf("LoadAll called %d times, want 2", n)
	}
}

// A store that cannot report a generation is never memoized: every issuance
// loads, which is the old behaviour and still correct.
func TestPolicySnapshotCacheSkipsStoreWithoutGeneration(t *testing.T) {
	calls := 0
	store := racedStore{first: completeAPIStore(t), later: completeAPIStore(t), calls: &calls}
	cache := &policySnapshotCache{}
	for range 3 {
		if _, err := cache.snapshot(store); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Fatalf("LoadAll called %d times, want one per request for an unversioned store", calls)
	}
}

// Concurrent issuances must collapse onto one load per generation and must
// never observe a snapshot whose version disagrees with its own document.
func TestPolicySnapshotCacheConcurrent(t *testing.T) {
	store := &countingStore{inner: completeAPIStore(t)}
	cache := &policySnapshotCache{}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			snap, err := cache.snapshot(store)
			if err != nil {
				t.Error(err)
				return
			}
			want, err := snap.Allowlist.CanonicalDigest()
			if err != nil {
				t.Error(err)
				return
			}
			if string(want) != string(snap.Digest) {
				t.Error("snapshot digest does not match its own document")
			}
		})
	}
	wg.Wait()
	if n := store.loadCount(); n != 1 {
		t.Fatalf("LoadAll called %d times under concurrency, want 1", n)
	}
}
