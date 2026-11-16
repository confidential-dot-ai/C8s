package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// cluster commits every command to every replica's store and answers with
// what the handle's own store made of it.
type cluster struct {
	mu      sync.Mutex
	stores  []*MemoryStore
	self    int
	commits int
}

func (c *cluster) Commit(cmd Command) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commits++
	var mine Result
	for i, s := range c.stores {
		if r := s.Apply(cmd); i == c.self {
			mine = r
		}
	}
	return mine, nil
}

// replicas builds n stores, a handle onto each, and the cluster view of the
// first.
func replicas(n, maxPaths, maxPerHolder, maxValue int) ([]*Handle, []*MemoryStore, *cluster) {
	stores := make([]*MemoryStore, n)
	for i := range stores {
		stores[i] = NewMemoryStore(maxPaths, maxPerHolder, maxValue)
	}
	views := make([]*cluster, n)
	handles := make([]*Handle, n)
	for i := range handles {
		views[i] = &cluster{stores: stores, self: i}
		handles[i] = stores[i].CommittedBy(views[i])
	}
	return handles, stores, views[0]
}

// The first committed write for a path wins at both replicas, and the second
// caller is handed the value that won.
func TestReplicatedSecretsFirstWriterWinsEverywhere(t *testing.T) {
	handles, stores, _ := replicas(2, 4, 2, 64)
	a := handles[0]
	b := handles[1]
	ctx := context.Background()
	web := WorkloadHolder("web")

	got, held, err := a.PutIfAbsent(ctx, "/p", []byte("from-a"), web)
	if err != nil || held.Exists || string(got) != "from-a" {
		t.Fatalf("first write: %q %+v %v", got, held, err)
	}
	got, held, err = b.PutIfAbsent(ctx, "/p", []byte("from-b"), web)
	if err != nil || !held.Exists || string(got) != "from-a" {
		t.Fatalf("second writer must be handed the first value: %q %+v %v", got, held, err)
	}
	for i, s := range stores {
		if v, err := s.Get(ctx, "/p"); err != nil || !bytes.Equal(v, []byte("from-a")) {
			t.Fatalf("replica %d holds %q (%v), want the committed value", i, v, err)
		}
	}
}

// A holder's quota is the cluster's: paths taken at one replica are charged
// to it at every other.
func TestReplicatedSecretsChargeTheQuotaOnce(t *testing.T) {
	handles, _, _ := replicas(2, 4, 2, 64)
	a := handles[0]
	b := handles[1]
	ctx := context.Background()
	web := WorkloadHolder("web")

	if _, _, err := a.PutIfAbsent(ctx, "/p", []byte("v"), web); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.PutIfAbsent(ctx, "/q", []byte("v"), web); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.PutIfAbsent(ctx, "/r", []byte("v"), web); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("third path = %v, want the holder quota", err)
	}
}

// An operator write replaces the value at every replica and moves the path's
// charge with it.
func TestReplicatedOperatorPutReachesEveryReplica(t *testing.T) {
	handles, stores, _ := replicas(2, 4, 2, 64)
	ctx := context.Background()

	if _, _, err := handles[0].PutIfAbsent(ctx, "/p", []byte("workload"), WorkloadHolder("web")); err != nil {
		t.Fatal(err)
	}
	held, err := handles[1].Put(ctx, "/p", []byte("operator"))
	if err != nil || !held.Exists || held.Origin != OriginWorkload {
		t.Fatalf("operator write: %+v %v", held, err)
	}
	for i, s := range stores {
		v, err := s.Get(ctx, "/p")
		if err != nil || !bytes.Equal(v, []byte("operator")) || s.Len() != 1 {
			t.Fatalf("replica %d holds %q, %d paths (%v)", i, v, s.Len(), err)
		}
	}
}

// A value over the per-value bound is refused before it reaches the log.
func TestOversizedValueNeverReachesTheLog(t *testing.T) {
	handles, _, committer := replicas(1, 4, 2, 64)
	ctx := context.Background()

	if _, err := handles[0].Put(ctx, "/big", bytes.Repeat([]byte("x"), 65)); err == nil {
		t.Fatal("an oversized value was accepted")
	}
	if committer.commits != 0 {
		t.Fatalf("%d commands committed, want none", committer.commits)
	}
}

// unavailable is a cluster with no leader or no quorum.
type unavailable struct{}

func (unavailable) Commit(Command) (Result, error) {
	return Result{}, fmt.Errorf("%w: no leader", ErrUnavailable)
}

// atCapacity is a cluster whose state is as large as a snapshot may be.
type atCapacity struct{}

func (atCapacity) Commit(Command) (Result, error) {
	return Result{}, fmt.Errorf("%w: 75%% of the snapshot bound", ErrCapacity)
}

// A write the cluster could not commit is a retryable 503, and one it refused
// on size is 507.
func TestOperatorPutReportsWhyTheClusterRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		commit Committer
		status int
		code   string
	}{
		"no quorum": {
			commit: unavailable{},
			status: http.StatusServiceUnavailable,
		},
		"at capacity": {
			commit: atCapacity{},
			status: http.StatusInsufficientStorage,
			code:   types.ErrorCodeStateCapacity,
		},
	} {
		t.Run(name, func(t *testing.T) {
			oh := newOperatorHarness(t)
			oh.h.Store = NewMemoryStore(8, 7, 64).CommittedBy(tc.commit)
			for _, overwrite := range []bool{false, true} {
				w, _ := doPut(oh.h, putRequest(t, "/tenant-a/db", []byte("v"), overwrite))
				if w.Code != tc.status {
					t.Errorf("overwrite=%v: status %d, want %d", overwrite, w.Code, tc.status)
				}
				if tc.code == "" {
					if w.Header().Get("Retry-After") == "" {
						t.Errorf("overwrite=%v: 503 carries no Retry-After", overwrite)
					}
					continue
				}
				if got := errorCode(t, w); got != tc.code {
					t.Errorf("overwrite=%v: error code %q, want %q", overwrite, got, tc.code)
				}
			}
		})
	}
}

// The workload path reports the same refusals, as errors its handler matches.
func TestWorkloadWriteReportsWhyTheClusterRefused(t *testing.T) {
	store := NewMemoryStore(4, 2, 64)
	ctx := context.Background()

	noQuorum := store.CommittedBy(unavailable{})
	if _, _, err := noQuorum.PutIfAbsent(ctx, "/p", []byte("v"), WorkloadHolder("web")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no quorum = %v, want ErrUnavailable", err)
	}
	full := store.CommittedBy(atCapacity{})
	if _, _, err := full.PutIfAbsent(ctx, "/p", []byte("v"), WorkloadHolder("web")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("at capacity = %v, want ErrCapacity", err)
	}
}

// A refusal every replica reaches alike crosses the log as itself.
func TestAppliedRefusalsCrossTheLog(t *testing.T) {
	handles, _, _ := replicas(1, 2, 1, 64)
	ctx := context.Background()

	if _, _, err := handles[0].PutIfAbsent(ctx, "/p", []byte("v"), WorkloadHolder("web")); err != nil {
		t.Fatal(err)
	}
	_, _, err := handles[0].PutIfAbsent(ctx, "/q", []byte("v"), WorkloadHolder("web"))
	if !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("quota refusal = %v, want ErrHolderQuota", err)
	}
	if _, err := handles[0].Put(ctx, "/q", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if _, err := handles[0].Put(ctx, "/r", []byte("v")); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("ceiling refusal = %v, want ErrStoreFull", err)
	}
}

// An unknown command is a replica meeting a write it cannot apply.
func TestUnknownCommandFails(t *testing.T) {
	if res := NewMemoryStore(4, 2, 64).Apply(Command{Op: "rename"}); res.Err(sentinels) == nil {
		t.Fatal("an unknown command applied cleanly")
	}
}

// A local write reports what the store made of it and nothing else.
func TestLocalHandleAppliesToItsOwnStore(t *testing.T) {
	store := NewMemoryStore(4, 2, 64)
	local := store.Local()
	ctx := context.Background()

	got, held, err := local.PutIfAbsent(ctx, "/p", []byte("v"), WorkloadHolder("web"))
	if err != nil || held.Exists || string(got) != "v" {
		t.Fatalf("local write: %q %+v %v", got, held, err)
	}
	if v, err := store.Get(ctx, "/p"); err != nil || string(v) != "v" {
		t.Fatalf("store holds %q (%v)", v, err)
	}
}

// A replica that joins a cluster takes every path, its value and the holder
// it is charged to, so quotas hold there as they do at its peers.
func TestASnapshotCarriesEveryPathAndItsHolder(t *testing.T) {
	ctx := context.Background()
	source := NewMemoryStore(4, 2, 64)
	web := WorkloadHolder("web")
	if _, _, err := source.Local().PutIfAbsent(ctx, "/web/one", []byte("one"), web); err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.Local().PutIfAbsent(ctx, "/web/two", []byte("two"), web); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Local().Put(ctx, "/operator", []byte("three")); err != nil {
		t.Fatal(err)
	}

	joining := NewMemoryStore(4, 2, 64)
	joining.Restore(source.Dump())

	for path, want := range map[string]string{"/web/one": "one", "/web/two": "two", "/operator": "three"} {
		value, err := joining.Get(ctx, path)
		if err != nil || string(value) != want {
			t.Fatalf("%s holds %q: %v", path, value, err)
		}
	}
	if _, _, err := joining.Local().PutIfAbsent(ctx, "/web/three", []byte("four"), web); !errors.Is(err, ErrHolderQuota) {
		t.Fatalf("a holder at its quota = %v, want ErrHolderQuota", err)
	}
	if paths := joining.TopHolders(1); len(paths) != 1 || paths[0].Paths != 2 {
		t.Fatalf("the busiest holder is %+v", paths)
	}
}

// Restoring replaces what the store held: a replica installing a snapshot
// holds the cluster's paths and none of its own.
func TestASnapshotReplacesTheStoreItIsInstalledOn(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(4, 2, 64)
	if _, err := store.Local().Put(ctx, "/its/own", []byte("value")); err != nil {
		t.Fatal(err)
	}
	store.Restore(nil)
	if _, err := store.Get(ctx, "/its/own"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the path survived the snapshot: %v", err)
	}
	if store.Len() != 0 {
		t.Fatalf("the store holds %d paths", store.Len())
	}
}
