package allowlist

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
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
	if err := st[1].ConsumeToken("a.b.other-sig"); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("a token spent at one replica is spendable at another: %v", err)
	}
	if err := st[0].PutWorkload("BAD NAME", w); !errors.Is(err, ErrInvalidWorkload) {
		t.Fatalf("invalid workload error lost its sentinel: %v", err)
	}
	ref := contents(t, st[0])
	for i, s := range st[1:] {
		if d := contents(t, s); !reflect.DeepEqual(d, ref) {
			t.Fatalf("replica %d diverged:\n%v\nvs\n%v", i+1, d, ref)
		}
	}
	v0, _ := st[0].Version()
	v2, _ := st[2].Version()
	if v0 != v2 || v0 == "1" {
		t.Fatalf("versions %s %s", v0, v2)
	}
}

// contents is every row of every table, rowids included: what replicas
// must agree on. Database images may differ in bytes.
func contents(t *testing.T, s *Store) map[string][]map[string]any {
	t.Helper()
	tables, err := s.db.Query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	tables.Close()
	out := map[string][]map[string]any{}
	for _, n := range names {
		rows, err := s.db.Query("SELECT rowid AS rowid_, * FROM " + n + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			row := map[string]any{}
			for i, c := range cols {
				row[c] = vals[i]
			}
			out[n] = append(out[n], row)
		}
		rows.Close()
	}
	return out
}

// A database image restores an identical store, into a file as into memory;
// an image that is not a database leaves the store as it was.
func TestSnapshotRoundTrip(t *testing.T) {
	st := replicated(t, 1)
	if err := st[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "gone", "db"} {
		if err := st[0].PutWorkload(name, oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st[0].DeleteWorkload("gone"); err != nil { // a rowid gap
		t.Fatal(err)
	}
	if err := st[0].ConsumeToken("x.y.z"); err != nil {
		t.Fatal(err)
	}
	image, err := st[0].Dump()
	if err != nil {
		t.Fatal(err)
	}
	mem, _ := OpenInMemory()
	defer mem.Close()
	file, err := OpenStore(filepath.Join(t.TempDir(), "allowlist.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for name, fresh := range map[string]*Store{"memory": &mem, "file": &file} {
		gen := fresh.Generation()
		if err := fresh.Restore(image); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, want := contents(t, fresh), contents(t, st[0]); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: restored store differs:\n%v\nvs\n%v", name, got, want)
		}
		if fresh.Generation() == gen {
			t.Fatalf("%s: restore did not invalidate cached views", name)
		}
		if err := fresh.ConsumeToken("x.y.z"); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("%s: restored store forgot a spent token", name)
		}
		before := contents(t, fresh)
		for what, b := range map[string][]byte{"garbage": []byte("not a database"), "truncated": image[:len(image)/2], "bad page": badPage(image)} {
			if err := fresh.Restore(b); err == nil {
				t.Errorf("%s: restore accepted a %s image", name, what)
			}
		}
		if !reflect.DeepEqual(contents(t, fresh), before) {
			t.Fatalf("%s: a refused image changed the store", name)
		}
	}
}

// An image from before the token window columns is migrated on restore.
func TestRestoreMigratesAnOlderImage(t *testing.T) {
	old, err := sql.Open("sqlite", memdbURI("old"))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if _, err := old.Exec("CREATE TABLE used_token (digest TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	tok := tokenAt(t0, "old")
	if _, err := old.Exec("INSERT INTO used_token VALUES (?)", tokenDigest(tok)); err != nil {
		t.Fatal(err)
	}
	conn, _ := old.Conn(context.Background())
	var image []byte
	if err := conn.Raw(func(dc any) error { image, err = dc.(imageConn).Serialize(); return err }); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	s, _ := OpenInMemory()
	defer s.Close()
	if err := s.Restore(image); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeToken(tok); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("migrated image: %v", err)
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
	msg := "operator token already used: it expired"
	if err := (Result{ErrKind: "token_reused", Err: msg}).Error(); !errors.Is(err, operatorauth.ErrTokenReused) || err.Error() != msg {
		t.Fatalf("error across the log: %v", err)
	}
}

// badPage is image with the b-tree page type of its last page broken.
func badPage(image []byte) []byte {
	b := slices.Clone(image)
	b[len(b)-int(binary.BigEndian.Uint16(b[16:18]))] = 0xee // header: page size
	return b
}
