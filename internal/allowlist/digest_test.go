package allowlist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// checkDigest fails unless the running digest equals one read from the rows.
func checkDigest(t *testing.T, s *Store, after string) {
	t.Helper()
	scan, err := s.ScanDigest()
	if err != nil {
		t.Fatal(err)
	}
	if s.Digest() != scan {
		t.Fatalf("after %s: running digest differs from the rows", after)
	}
}

// Every write path keeps the running digest equal to the rows' digest,
// including writes that fail and transactions that roll back.
func TestDigestFollowsEveryWrite(t *testing.T) {
	st := replicated(t, 1)
	s := st[0]
	checkDigest(t, s, "open")
	wA, wB := oneContainerWorkload(mustParseDigest(t, digestA)), oneContainerWorkload(mustParseDigest(t, digestC))
	al := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{"x": wA, "y": wB}}
	steps := []struct {
		name string
		do   func() error
	}{
		{"start journal", s.StartJournal},
		{"put", func() error { return s.PutWorkload("web", wA) }},
		{"put again (update)", func() error { return s.PutWorkload("web", wB) }},
		{"seed", func() error {
			_, _, err := s.SeedWorkloads(map[string]pkgallowlist.Workload{"seeded": wA, "web": wA})
			return err
		}},
		{"bad name (refused)", func() error { s.PutWorkload("BAD NAME", wA); return nil }},
		{"replace all", func() error { return s.ReplaceAll(al) }},
		{"replace all signed", func() error { return s.ReplaceAllIfMatch(al, "", "tok.en.sig") }},
		{"resign (replace)", func() error { return s.ReplaceAllIfMatch(al, "", "tok.en.sig2") }},
		{"token", func() error { return s.ConsumeToken("a.b.sig") }},
		{"token reused (rolled back)", func() error { s.ConsumeToken("a.b.sig"); return nil }},
		{"bad routes (refused)", func() error { s.ReplaceRoutes(routes.Envelope{Manifest: []byte("{")}, ""); return nil }},
		{"delete", func() error { _, err := s.DeleteWorkload("x"); return err }},
		{"prune", func() error { _, err := s.pruneHistory(2); return err }},
		{"replace all empty", func() error { return s.ReplaceAll(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}) }},
		{"rolled back transaction", func() error {
			tx, err := s.db.Begin()
			if err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO workload_entry (name, entry_json) VALUES ('ghost', '{}')"); err != nil {
				return err
			}
			return tx.Rollback()
		}},
		{"vacuum into", func() error { _, err := s.Dump(); return err }},
	}
	for _, step := range steps {
		if err := step.do(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		checkDigest(t, s, step.name)
	}
}

// Stores that hold the same rows have the same digest however they got
// there: a log replay, a restored VACUUM INTO image, a file database, and
// one whose rowids differ (an extra row inserted and deleted) and that saw
// a rolled-back transaction and refused commands.
func TestDigestIsTheContentNotTheHistory(t *testing.T) {
	st := replicated(t, 2)
	odd := st[1]
	// Advance odd's rowids and roll back a write before the replicated ones.
	if _, err := odd.db.Exec("INSERT INTO used_token (digest) VALUES ('scratch1'), ('scratch2')"); err != nil {
		t.Fatal(err)
	}
	tx, _ := odd.db.Begin()
	_, _ = tx.Exec("INSERT INTO used_token (digest) VALUES ('never')")
	_ = tx.Rollback()
	if err := st[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	w := oneContainerWorkload(mustParseDigest(t, digestA))
	for _, n := range []string{"a", "b", "c"} {
		if err := st[0].PutWorkload(n, w); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st[1].DeleteWorkload("b"); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"t1.o.k", "t2.o.k"} {
		if err := st[1].ConsumeToken(tok); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := odd.db.Exec("DELETE FROM used_token WHERE digest LIKE 'scratch%'"); err != nil {
		t.Fatal(err)
	}
	if r := odd.Apply(Command{Op: "nope"}); r.Error() == nil { // a failed apply on one replica
		t.Fatal("unknown op applied")
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
	if err := mem.Restore(image); err != nil {
		t.Fatal(err)
	}
	if err := file.Restore(image); err != nil {
		t.Fatal(err)
	}
	fromImage, err := ImageDigest(image)
	if err != nil {
		t.Fatal(err)
	}
	want := st[0].Digest()
	for name, got := range map[string][32]byte{"replica": odd.Digest(), "memory restore": mem.Digest(), "file restore": file.Digest(), "image": fromImage} {
		if got != want {
			t.Errorf("%s: digest differs from the replica that wrote the rows", name)
		}
	}
	for name, s := range map[string]*Store{"odd": odd, "memory": &mem, "file": &file} {
		checkDigest(t, s, name)
	}
	var rowid0, rowid1 int64
	_ = st[0].db.QueryRow("SELECT MAX(rowid) FROM used_token").Scan(&rowid0)
	_ = odd.db.QueryRow("SELECT MAX(rowid) FROM used_token").Scan(&rowid1)
	if rowid0 == rowid1 {
		t.Fatalf("test setup: rowids agree (%d), so the test does not show they are left out", rowid0)
	}
}

// A value changed under the store (here a write through a connection
// without the hooks, as corruption would) makes the rows' digest differ
// from the running one, and an image whose rows are not the digest it is
// restored against is refused without touching the store.
func TestDigestSeesContentChangedUnderTheStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.StartJournal(); err != nil {
		t.Fatal(err)
	}
	if err := s.PutWorkload("web", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	good, err := s.Dump()
	if err != nil {
		t.Fatal(err)
	}
	want := s.Digest()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("UPDATE workload_entry SET entry_json = replace(entry_json, 'a1', 'a0')"); err != nil {
		t.Fatal(err)
	}
	scan, err := s.ScanDigest()
	if err != nil {
		t.Fatal(err)
	}
	if scan == s.Digest() {
		t.Fatal("a value changed under the store went unseen")
	}
	rotted, err := s.Dump()
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := OpenInMemory()
	defer fresh.Close()
	before := fresh.Digest()
	if err := fresh.RestoreDigest(rotted, want); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("rotted image restored against the applied digest: %v", err)
	}
	if fresh.Digest() != before {
		t.Fatal("a refused image changed the store")
	}
	if err := fresh.RestoreDigest(good, want); err != nil {
		t.Fatal(err)
	}
	checkDigest(t, &fresh, "verified restore")
}

// BenchmarkWrite measures a workload write with the digest hooks and
// without (a store opened as before them), over documents of n workloads:
// each write journals the whole document, so the hooks hash it once more.
func BenchmarkWrite(b *testing.B) {
	for _, n := range []int{10, 1000, 10000} {
		for _, hooks := range []bool{false, true} {
			b.Run(fmt.Sprintf("workloads=%d/hooks=%v", n, hooks), func(b *testing.B) {
				var s Store
				if hooks {
					var err error
					if s, err = OpenInMemory(); err != nil {
						b.Fatal(err)
					}
				} else {
					uri := memdbURI("plain")
					db, err := sql.Open("sqlite", uri)
					if err != nil {
						b.Fatal(err)
					}
					if err := initDB(context.Background(), db); err != nil {
						b.Fatal(err)
					}
					s = Store{db: db, uri: uri, dig: &contentDigest{}}
				}
				defer s.Close()
				ws := map[string]pkgallowlist.Workload{}
				for i := range n {
					ws[fmt.Sprintf("w%05d", i)] = benchWorkload(i)
				}
				if _, _, err := s.SeedWorkloads(ws); err != nil {
					b.Fatal(err)
				}
				if err := s.StartJournal(); err != nil {
					b.Fatal(err)
				}
				doc, _, _ := s.LoadAll()
				body, _ := doc.Canonical()
				b.ReportMetric(float64(len(body)), "doc-bytes")
				i := 0
				for b.Loop() {
					i++
					if err := s.PutWorkload("w00000", benchWorkload(n+i)); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func benchWorkload(i int) pkgallowlist.Workload {
	d, _ := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+1))
	return oneContainerWorkload(d)
}
