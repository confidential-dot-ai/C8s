package allowlist

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// fanout is a Replicator that applies every command to each store in order,
// as a committed Raft log would, and returns the proposer's result.
type fanout struct {
	mu     sync.Mutex
	stores []*Store
	self   int
}

func (f *fanout) Replicate(cmd Command) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var mine Result
	for i, s := range f.stores {
		r := s.Apply(cmd)
		if i == f.self {
			mine = r
		}
	}
	return mine, nil
}

func replicated(t *testing.T, n int) []*Store {
	t.Helper()
	stores := make([]*Store, n)
	for i := range stores {
		s, err := OpenInMemory()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		stores[i] = &s
	}
	for i, s := range stores {
		s.SetReplicator(&fanout{stores: stores, self: i})
	}
	return stores
}

// Writes made through any replica leave every replica with the same rows,
// history (timestamps included), version and spent tokens, and errors keep
// their sentinels.
func TestReplicatedStoresConverge(t *testing.T) {
	st := replicated(t, 3)
	if err := st[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	w := oneContainerWorkload(mustParseDigest(t, digestA))
	if err := st[1].PutWorkload("web", w); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st[2].SeedWorkloads(map[string]pkgallowlist.Workload{"seeded": w}); err != nil {
		t.Fatal(err)
	}
	if found, err := st[0].DeleteWorkload("web"); err != nil || !found {
		t.Fatalf("delete: %v %v", found, err)
	}
	if err := st[2].ConsumeToken("a.b.sig"); err != nil {
		t.Fatal(err)
	}
	if err := st[1].ConsumeToken("a.b.other-sig"); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("a token spent at one replica is spendable at another: %v", err)
	}
	if err := st[0].PutWorkload("BAD NAME", w); !errors.Is(err, ErrInvalidWorkload) {
		t.Fatalf("invalid workload error lost its sentinel: %v", err)
	}
	ref, err := st[0].Dump()
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range st[1:] {
		d, err := s.Dump()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(d, ref) {
			t.Fatalf("replica %d diverged:\n%v\nvs\n%v", i+1, d, ref)
		}
	}
	v0, _ := st[0].Version()
	v2, _ := st[2].Version()
	if v0 != v2 || v0 == "1" {
		t.Fatalf("versions %s %s", v0, v2)
	}
}

// A snapshot restores an identical store, through JSON.
func TestSnapshotRoundTrip(t *testing.T) {
	st := replicated(t, 1)
	if err := st[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	if err := st[0].PutWorkload("web", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	if err := st[0].ConsumeToken("x.y.z"); err != nil {
		t.Fatal(err)
	}
	sn, err := st[0].Dump()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sn.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Snapshot
	if err := back.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	fresh, _ := OpenInMemory()
	defer fresh.Close()
	if err := fresh.Restore(back); err != nil {
		t.Fatal(err)
	}
	got, _ := fresh.Dump()
	if !reflect.DeepEqual(got, sn) {
		t.Fatalf("restored store differs:\n%v\nvs\n%v", got, sn)
	}
	if err := fresh.ConsumeToken("x.y.z"); !errors.Is(err, ErrTokenReused) {
		t.Fatal("restored store forgot a spent token")
	}
	bad := Snapshot{"workload_entry": {{"name; DROP": "x"}}}
	if err := fresh.Restore(bad); err == nil {
		t.Fatal("restore accepted a bad column name")
	}
}

// Whole-document writes, their operator signature and malformed commands
// cross the replication boundary like local writes.
func TestReplicatedWholeDocumentAndMalformed(t *testing.T) {
	st := replicated(t, 2)
	if err := st[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	al := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{"web": oneContainerWorkload(mustParseDigest(t, digestA))}}
	if err := st[1].ReplaceAll(al); err != nil {
		t.Fatal(err)
	}
	body, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := st[0].SignPolicy(body, "tok.en.sig"); err != nil {
		t.Fatal(err)
	}
	if tok, ok, err := st[1].Signature(objectDigest(body)); err != nil || !ok || tok != "tok.en.sig" {
		t.Fatalf("signature not replicated: %q %v %v", tok, ok, err)
	}
	if err := st[0].ReplaceAll(nil); err == nil {
		t.Fatal("nil document replaced")
	}
	if err := st[0].ReplaceRoutes(routes.Envelope{Manifest: []byte("{")}, ""); err == nil {
		t.Fatal("unparsable route manifest replicated")
	}
	if _, _, err := st[0].SeedWorkloads(nil); err != nil {
		t.Fatal(err)
	}
	for name, cmd := range map[string]Command{
		"unknown op":        {Op: "nope"},
		"put without entry": {Op: OpPutWorkload, Name: "x"},
		"routes without":    {Op: OpReplaceRoutes},
	} {
		if r := st[0].Apply(cmd); r.Error() == nil {
			t.Errorf("%s applied", name)
		}
	}
	if (Result{ErrKind: "token_reused", Err: ErrTokenReused.Error()}).Error() != ErrTokenReused {
		t.Fatal("a bare sentinel must come back as itself")
	}
}
