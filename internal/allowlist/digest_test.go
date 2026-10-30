package allowlist

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Fails unless the digest the store keeps is the digest of its rows.
func sameAsItsRows(t *testing.T, s *Store, after string) {
	t.Helper()
	scanned, kept, err := s.ScanDigest()
	if err != nil {
		t.Fatalf("after %s: %v", after, err)
	}
	if scanned != kept {
		t.Fatalf("after %s: the digest the store keeps differs from the digest of its rows", after)
	}
}

func TestTheDigestFollowsEveryWrite(t *testing.T) {
	store, allowlist := openInMemoryStore(t)
	sameAsItsRows(t, store, "open")
	workload := oneContainerWorkload(mustParseDigest(t, digestA))
	document := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"web": workload},
	}
	writes := []struct {
		what  string
		write func() error
	}{
		{"start journal", allowlist.StartJournal},
		{"seed", func() error {
			_, _, err := allowlist.SeedWorkloads(map[string]pkgallowlist.Workload{"seeded": workload})
			return err
		}},
		{"replace the document", func() error {
			return allowlist.ReplaceAll(document, OperatorWrite{Signature: "tok.en.sig"})
		}},
		{"replace it again", func() error {
			return allowlist.ReplaceAll(document, OperatorWrite{Signature: "tok.en.sig2"})
		}},
		{"replace it with an empty one", func() error {
			return allowlist.ReplaceAll(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}, OperatorWrite{})
		}},
		{"spend a token", func() error { return allowlist.ConsumeToken(tokenAt(t0, "write")) }},
		{"spend it again (refused)", func() error {
			_ = allowlist.ConsumeToken(tokenAt(t0, "write"))
			return nil
		}},
		{"store routes", func() error { return allowlist.ReplaceRoutes(routesEnvelope(2, "token-2"), "") }},
		{"store a manifest that does not parse (refused)", func() error {
			_ = allowlist.ReplaceRoutes(routes.Envelope{Manifest: []byte("{")}, "")
			return nil
		}},
		{"raise the version", func() error {
			_, err := store.RaiseVersion(t0)
			return err
		}},
		{"prune the history", func() error { return store.pruneHistory(1) }},
		{"roll a transaction back", func() error {
			tx, err := store.db.Begin()
			if err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO workload_entry (name, entry_json) VALUES ('ghost', '{}')"); err != nil {
				return err
			}
			return tx.Rollback()
		}},
		{"dump an image", func() error {
			_, err := store.Dump()
			return err
		}},
	}
	for _, write := range writes {
		if err := write.write(); err != nil {
			t.Fatalf("%s: %v", write.what, err)
		}
		sameAsItsRows(t, store, write.what)
	}
}

func TestACommitAfterARolledBackStatementIsRefused(t *testing.T) {
	store, _ := openInMemoryStore(t)
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	duplicate := "INSERT INTO used_token (digest, iat_unix, exp_unix) SELECT 'spent', 1, 2 UNION ALL SELECT 'spent', 1, 2"
	if _, err := tx.Exec(duplicate); err == nil {
		t.Fatal("a statement inserting one digest twice was taken")
	}
	if _, err := tx.Exec("INSERT INTO used_token (digest, iat_unix, exp_unix) VALUES ('kept', 1, 2)"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("a transaction whose statement SQLite rolled back was committed")
	}
	sameAsItsRows(t, store, "a refused commit")
	if spent := spentTokens(t, store); spent != 0 {
		t.Fatalf("the refused transaction left %d spent tokens", spent)
	}

	// The connection serves the writes that follow.
	if err := store.Local().ConsumeToken(tokenAt(t0, "after")); err != nil {
		t.Fatal(err)
	}
	sameAsItsRows(t, store, "a write after a refused commit")
}

func TestAStatementThatChangedNoRowLeavesItsTransactionAlone(t *testing.T) {
	store, _ := openInMemoryStore(t)
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO no_such_table (digest) VALUES ('x')"); err == nil {
		t.Fatal("a statement on a table the store has not got was taken")
	}
	if _, err := tx.Exec("INSERT INTO used_token (digest, iat_unix, exp_unix) VALUES ('kept', 1, 2)"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("a transaction whose rows all reached the database: %v", err)
	}
	sameAsItsRows(t, store, "a commit after a statement that changed nothing")
	if spent := spentTokens(t, store); spent != 1 {
		t.Fatalf("the transaction stored %d spent tokens, want 1", spent)
	}
}

func spentTokens(t *testing.T, s *Store) int {
	t.Helper()
	var spent int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM used_token").Scan(&spent); err != nil {
		t.Fatal(err)
	}
	return spent
}

func TestTheHooksAndAScanNameARowAlike(t *testing.T) {
	store, _ := openInMemoryStore(t)
	if _, err := store.db.Exec("CREATE TABLE classes (t TEXT, i INTEGER, b BLOB, n TEXT)"); err != nil {
		t.Fatal(err)
	}
	rows := []string{
		"INSERT INTO classes VALUES ('text', -7, X'00ff', NULL)",
		"INSERT INTO classes VALUES ('', 0, X'', NULL)",
		"INSERT INTO classes VALUES (NULL, NULL, NULL, 'only text')",
	}
	for _, row := range rows {
		if _, err := store.db.Exec(row); err != nil {
			t.Fatal(err)
		}
		sameAsItsRows(t, store, row)
	}
	if _, err := store.db.Exec("UPDATE classes SET i = 9, b = X'0102' WHERE t = 'text'"); err != nil {
		t.Fatal(err)
	}
	sameAsItsRows(t, store, "an update of every class")
	if _, err := store.db.Exec("DELETE FROM classes"); err != nil {
		t.Fatal(err)
	}
	sameAsItsRows(t, store, "a delete of every row")
}

func TestAStoreWithAColumnTheDigestCannotNameDoesNotOpen(t *testing.T) {
	columns := map[string]struct{ declared, value string }{
		"a real SQLite keeps as an integer": {"REAL", "1.5"},
		"a stamp the driver parses":         {"TIMESTAMP", "'2026-01-01T00:00:00Z'"},
	}
	for what, column := range columns {
		path := filepath.Join(t.TempDir(), "allowlist.db")
		store, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("CREATE TABLE named (x " + column.declared + ")"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("INSERT INTO named (x) VALUES (" + column.value + ")"); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(path); err == nil {
			t.Errorf("a store with %s opened", what)
		}
	}
}

func TestTheDigestIsTheContentAndNotTheHistory(t *testing.T) {
	stores, replicas := replicated(t, 2)
	written := stores[0]
	other := stores[1]
	spent := spendRowids(t, other)
	if err := replicas[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		putEntry(t, replicas[1], name, oneContainerWorkload(mustParseDigest(t, digestA)))
	}
	deleteEntry(t, replicas[0], "b")
	if err := replicas[1].ConsumeToken(tokenAt(t0, "write")); err != nil {
		t.Fatal(err)
	}
	spent()

	image, err := written.Dump()
	if err != nil {
		t.Fatal(err)
	}
	memory, _ := openInMemoryStore(t)
	file, err := OpenStore(filepath.Join(t.TempDir(), "allowlist.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	for name, fresh := range map[string]*Store{
		"memory": memory,
		"file":   file,
	} {
		if err := fresh.Restore(image); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	want := written.Digest()
	for name, s := range map[string]*Store{
		"the other replica": other,
		"memory":            memory,
		"file":              file,
	} {
		if s.Digest() != want {
			t.Errorf("%s: the digest differs from the store that wrote the rows", name)
		}
		sameAsItsRows(t, s, name)
	}
}

// Numbers the store's spent tokens from a higher rowid than its replica, so
// content is all their digests can agree on; the returned function gives the
// rows back.
func spendRowids(t *testing.T, s *Store) func() {
	t.Helper()
	if _, err := s.db.Exec("INSERT INTO used_token (digest, iat_unix, exp_unix) VALUES ('scratch', 1, 2)"); err != nil {
		t.Fatal(err)
	}
	before := highestRowid(t, s, "used_token")
	return func() {
		t.Helper()
		if _, err := s.db.Exec("DELETE FROM used_token WHERE digest = 'scratch'"); err != nil {
			t.Fatal(err)
		}
		if highestRowid(t, s, "used_token") <= before {
			t.Fatal("the spent rowids came back, so the stores may be agreeing on them")
		}
	}
}

func highestRowid(t *testing.T, s *Store, table string) int64 {
	t.Helper()
	var highest int64
	if err := s.db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM " + table).Scan(&highest); err != nil {
		t.Fatal(err)
	}
	return highest
}

func TestTheDigestSeesContentChangedUnderTheStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	allowlist := store.Local()
	if err := allowlist.StartJournal(); err != nil {
		t.Fatal(err)
	}
	putEntry(t, allowlist, "web", oneContainerWorkload(mustParseDigest(t, digestA)))
	sameAsItsRows(t, store, "a write")

	under, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { under.Close() })
	if _, err := under.Exec("UPDATE workload_entry SET entry_json = 'changed under the store'"); err != nil {
		t.Fatal(err)
	}
	scanned, kept, err := store.ScanDigest()
	if err != nil {
		t.Fatal(err)
	}
	if scanned == kept {
		t.Fatal("a value changed under the store went unseen")
	}
}

func TestAReopenedStoreDigestsWhatItHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	allowlist := store.Local()
	if err := allowlist.StartJournal(); err != nil {
		t.Fatal(err)
	}
	putEntry(t, allowlist, "web", oneContainerWorkload(mustParseDigest(t, digestA)))
	want := store.Digest()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	if reopened.Digest() != want {
		t.Fatal("a reopened store digests something other than the rows it holds")
	}
}

// An operator write and a whole-database scan, over documents of n workloads.
func BenchmarkDigest(b *testing.B) {
	for _, n := range []int{10, 1000, 10000} {
		b.Run(fmt.Sprintf("write/workloads=%d", n), func(b *testing.B) {
			_, allowlist := benchmarkStore(b, n)
			i := 0
			for b.Loop() {
				i++
				if err := allowlist.ReplaceAll(benchmarkDocument(n, i), OperatorWrite{}); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("scan/workloads=%d", n), func(b *testing.B) {
			store, _ := benchmarkStore(b, n)
			for b.Loop() {
				if _, _, err := store.ScanDigest(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkStore(b *testing.B, workloads int) (*Store, *Handle) {
	b.Helper()
	store, err := OpenInMemory()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { store.Close() })
	allowlist := store.Local()
	if err := allowlist.StartJournal(); err != nil {
		b.Fatal(err)
	}
	if err := allowlist.ReplaceAll(benchmarkDocument(workloads, 0), OperatorWrite{}); err != nil {
		b.Fatal(err)
	}
	return store, allowlist
}

func benchmarkDocument(workloads, revision int) *pkgallowlist.Allowlist {
	document := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: make(map[string]pkgallowlist.Workload, workloads),
	}
	for i := range workloads {
		digest, _ := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+revision*workloads+1))
		document.Workloads[fmt.Sprintf("w%05d", i)] = oneContainerWorkload(digest)
	}
	return document
}
