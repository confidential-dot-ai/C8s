package allowlist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// fanout stands in for a cluster's log: every store applies every command in
// order, and command and result travel as JSON.
type fanout struct {
	mu     sync.Mutex
	stores []*Store
	self   int
}

func (f *fanout) Commit(cmd Command) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, err := json.Marshal(cmd)
	if err != nil {
		return Result{}, err
	}
	var committed Command
	if err := json.Unmarshal(raw, &committed); err != nil {
		return Result{}, err
	}
	var mine Result
	for i, s := range f.stores {
		if r := s.Apply(committed); i == f.self {
			mine = r
		}
	}
	raw, err = json.Marshal(mine)
	if err != nil {
		return Result{}, err
	}
	var answer Result
	return answer, json.Unmarshal(raw, &answer)
}

// replicated is n allowlists whose writes every one of them applies.
func replicated(t *testing.T, n int) ([]*Store, []*Handle) {
	t.Helper()
	stores := make([]*Store, n)
	for i := range stores {
		store, err := OpenInMemory()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		stores[i] = store
	}
	handles := make([]*Handle, n)
	for i, store := range stores {
		handles[i] = store.CommittedBy(&fanout{
			stores: stores,
			self:   i,
		})
	}
	return stores, handles
}

// Writes through any replica leave every replica with the same rows, history,
// version and spent tokens, and a refusal keeps its sentinel.
func TestReplicatedStoresConverge(t *testing.T) {
	stores, st := replicated(t, 3)
	if err := st[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	w := oneContainerWorkload(mustParseDigest(t, digestA))
	if _, _, err := st[2].SeedWorkloads(map[string]pkgallowlist.Workload{"seeded": w}); err != nil {
		t.Fatal(err)
	}
	al := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"web": w},
	}
	body, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	version, err := st[1].Version()
	if err != nil {
		t.Fatal(err)
	}
	if err := st[1].ReplaceAll(al, OperatorWrite{
		Version:   version,
		Signature: "tok.en.sig",
	}); err != nil {
		t.Fatal(err)
	}
	if token, ok, err := st[2].Signature(objectDigest(body)); err != nil || !ok || token != "tok.en.sig" {
		t.Fatalf("the signature of a write at another replica = %q, %v, %v", token, ok, err)
	}
	if err := st[0].ReplaceAll(al, OperatorWrite{Version: version}); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("a write on the version another replica replaced = %v, want ErrVersionMismatch", err)
	}
	token := tokenAt(t0, "write")
	if err := st[2].ConsumeToken(token); err != nil {
		t.Fatal(err)
	}
	if err := st[1].ConsumeToken(signedPart(token) + ".another-encoding"); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("a token spent at one replica is spendable at another: %v", err)
	}

	ref := contents(t, stores[0])
	for i, s := range stores[1:] {
		if got := contents(t, s); !reflect.DeepEqual(got, ref) {
			t.Fatalf("replica %d diverged:\n%v\nvs\n%v", i+1, got, ref)
		}
	}
}

// contents is every row of every table, rowids included; images may differ.
func contents(t *testing.T, s *Store) map[string][]map[string]any {
	t.Helper()
	tables, err := s.db.Query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	tables.Close()
	out := map[string][]map[string]any{}
	for _, name := range names {
		rows, err := s.db.Query("SELECT rowid AS rowid_, * FROM " + name + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			into := make([]any, len(columns))
			for i := range values {
				into[i] = &values[i]
			}
			if err := rows.Scan(into...); err != nil {
				t.Fatal(err)
			}
			row := map[string]any{}
			for i, c := range columns {
				row[c] = values[i]
			}
			out[name] = append(out[name], row)
		}
		rows.Close()
	}
	return out
}

func TestCommandsAreJournaledAtTheirOwnTime(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_000)
	w := oneContainerWorkload(mustParseDigest(t, digestA))
	al := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"web": w},
	}
	for _, cmd := range []Command{
		{
			Op:   OpStartJournal,
			AtMS: at.UnixMilli(),
		},
		{
			Op:        OpReplaceAll,
			Allowlist: al,
			AtMS:      at.Add(time.Second).UnixMilli(),
		},
	} {
		stores, _ := replicated(t, 2)
		for _, s := range stores {
			if r := s.Apply(cmd); r.Message != "" {
				t.Fatalf("%s: %+v", cmd.Op, r)
			}
			history, err := s.History()
			if err != nil {
				t.Fatal(err)
			}
			if got := history[len(history)-1].PublishedAt; !got.Equal(time.UnixMilli(cmd.AtMS).UTC()) {
				t.Fatalf("%s journaled at %s, want %s", cmd.Op, got, time.UnixMilli(cmd.AtMS).UTC())
			}
		}
	}
}

// A command no replica can apply fails at every replica without changing one.
func TestMalformedCommandsAreRefused(t *testing.T) {
	stores, st := replicated(t, 2)
	if err := st[0].ReplaceAll(nil, OperatorWrite{}); err == nil {
		t.Fatal("a write without a document was applied")
	}
	if err := st[0].ReplaceRoutes(routes.Envelope{Manifest: []byte("{")}, ""); err == nil {
		t.Fatal("an unparsable route manifest was applied")
	}
	at := time.Now().UnixMilli()
	for name, cmd := range map[string]Command{
		"unknown op": {
			Op:   "nope",
			AtMS: at,
		},
		"routes without one": {
			Op:   OpReplaceRoutes,
			AtMS: at,
		},
		"a history of none": {
			Op:   OpPruneHistory,
			AtMS: at,
		},
		"document without one": {
			Op:   OpReplaceAll,
			AtMS: at,
		},
		"no time": {Op: OpStartJournal},
	} {
		if r := stores[0].Apply(cmd); r.Err(sentinels) == nil {
			t.Errorf("%s: applied", name)
		}
	}
	if got := contents(t, stores[0]); !reflect.DeepEqual(got, contents(t, stores[1])) {
		t.Fatal("a refused command changed one replica")
	}
}

// A failure of this replica's own database is marked as such; a refusal every
// replica shares is not.
func TestLocalStoreFaultClassification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	allowlist := store.Local()

	token := tokenAt(t0, "a")
	if err := allowlist.ConsumeToken(token); err != nil {
		t.Fatal(err)
	}
	if r := store.Apply(Command{
		Op:    OpConsumeToken,
		Token: token,
		AtMS:  t0 * 1000,
	}); r.LocalStoreFault() {
		t.Fatalf("a replayed token read as a fault of the database: %+v", r)
	}
	if r := store.Apply(Command{
		Op:   "nope",
		AtMS: t0 * 1000,
	}); r.LocalStoreFault() {
		t.Fatalf("an unknown command read as a fault of the database: %+v", r)
	}

	// The database itself: another connection holds it exclusively.
	lock, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	lock.SetMaxOpenConns(1)
	if _, err := lock.Exec("BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	r := store.Apply(Command{
		Op:    OpConsumeToken,
		Token: tokenAt(t0, "b"),
		AtMS:  t0 * 1000,
	})
	if !r.LocalStoreFault() {
		t.Fatalf("a write against a locked database: %+v, want a local store fault", r)
	}
	if err := allowlist.ConsumeToken(tokenAt(t0, "c")); err == nil {
		t.Fatal("a write against a locked database succeeded")
	}
	if _, _, err := store.LoadAll(); !IsLocalStoreFault(err) {
		t.Fatalf("a read of a locked database = %v, want a local store fault", err)
	}
	if _, err := lock.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
}
