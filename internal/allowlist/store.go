package allowlist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Store provides persistent storage for the CDS allowlist using SQLite.
//
// `workload_entry` holds one canonical allowlist.Workload JSON per named entry,
// `workload_entry_digest` indexes each container digest for membership, and
// `allowlist_version` is the counter every mutation bumps (the worker pull
// ETag).
type Store struct {
	mu sync.Mutex
	db *sql.DB
	// gen counts committed mutations in this process. It is the invalidation
	// signal for a reader that memoizes a whole-document snapshot
	// (internal/cmds/cds).
	gen uint64
	// authority, lease and started are set once by StartJournal.
	authority string
	lease     time.Duration
	started   time.Time
	// state memoizes State until the next committed mutation.
	state    *State
	stateGen uint64
}

// roleInit / roleMain label the two container partitions in the digest index.
const (
	roleInit = "init"
	roleMain = "main"
)

// ErrInvalidWorkload marks a workload rejected by allowlist validation (a
// malformed name or container), so the handler answers 422 rather than 500.
var ErrInvalidWorkload = errors.New("invalid workload entry")

const initSQL = `
CREATE TABLE IF NOT EXISTS allowlist_version (
	version TEXT NOT NULL DEFAULT '1'
);
INSERT INTO allowlist_version (version)
	SELECT '1' WHERE NOT EXISTS (SELECT 1 FROM allowlist_version);
CREATE TABLE IF NOT EXISTS workload_entry (
	name       TEXT PRIMARY KEY,
	entry_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workload_entry_digest (
	digest     TEXT NOT NULL,
	entry_name TEXT NOT NULL,
	role       TEXT NOT NULL,
	PRIMARY KEY (digest, entry_name, role)
);
`

// OpenStore opens (or creates) a SQLite-backed allowlist store at the given path.
func OpenStore(path string) (Store, error) {
	_, err := os.Stat(path)
	isNew := os.IsNotExist(err)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Store{}, fmt.Errorf("open allowlist db: %w", err)
	}

	if isNew {
		slog.Warn("allowlist db did not exist, creating", "path", path)
	}

	if _, err := db.Exec(initSQL + journalSQL); err != nil {
		db.Close()
		return Store{}, fmt.Errorf("init allowlist schema: %w", err)
	}

	return Store{db: db}, nil
}

// OpenInMemory opens an in-memory allowlist store, useful for testing.
func OpenInMemory() (Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return Store{}, err
	}
	if _, err := db.Exec(initSQL + journalSQL); err != nil {
		db.Close()
		return Store{}, err
	}
	return Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// LoadAll builds the full allowlist document and returns it with the version
// string (the ETag). It backs GET /allowlist.
func (s *Store) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var version string
	if err := s.db.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&version); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, "", err
		}
		version = "1"
	}

	workloads, err := loadWorkloadsTx(s.db)
	if err != nil {
		return nil, "", err
	}

	return &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: workloads,
	}, version, nil
}

func loadWorkloadsTx(q interface {
	Query(string, ...any) (*sql.Rows, error)
}) (map[string]pkgallowlist.Workload, error) {
	rows, err := q.Query("SELECT name, entry_json FROM workload_entry")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	workloads := map[string]pkgallowlist.Workload{}
	for rows.Next() {
		var name, entryJSON string
		if err := rows.Scan(&name, &entryJSON); err != nil {
			return nil, err
		}
		var w pkgallowlist.Workload
		if err := json.Unmarshal([]byte(entryJSON), &w); err != nil {
			return nil, fmt.Errorf("decode workload %q: %w", name, err)
		}
		workloads[name] = w
	}
	return workloads, rows.Err()
}

// Contains reports whether digest is indexed as a workload container. It is
// the coarse per-digest gate the /attest handler applies to every claimed
// container image (docs/ratls.md).
func (s *Store) Contains(digest types.Digest) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var one int
	err := s.db.QueryRow(
		"SELECT 1 FROM workload_entry_digest WHERE digest = ? LIMIT 1", digest.String(),
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Version returns the current allowlist version counter — the same value the
// worker pull ETag carries. It is a single-row read, so a caller that must not
// pay for LoadAll on every request can use it to decide whether a cached
// document is still current.
func (s *Store) Version() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var version string
	if err := s.db.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&version); err != nil {
		return "", fmt.Errorf("read allowlist version: %w", err)
	}
	return version, nil
}

// commitTx journals, commits a mutating transaction and records the mutation
// for snapshot-cache invalidation. Every write path goes through it.
// Callers must hold s.mu.
func (s *Store) commitTx(tx *sql.Tx) error {
	if err := s.journalTx(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.gen++
	return nil
}

// Generation returns the number of mutations committed to this store in this
// process. A reader that caches a derived view invalidates it when the value
// changes; it never goes backwards, and it costs no database round-trip.
func (s *Store) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

// bumpVersionTx increments the store version within tx. The version is the
// worker pull ETag, so it is bumped once per mutation that changes the set.
func bumpVersionTx(tx *sql.Tx) error {
	_, err := tx.Exec(
		"UPDATE allowlist_version SET version = CAST(CAST(version AS INTEGER) + 1 AS TEXT)",
	)
	return err
}

// SeedWorkloads adds every workload entry whose name is not already present, in
// a single transaction, and returns the number added. Additive and idempotent:
// an existing entry is left untouched and the version is bumped at most once,
// only when at least one entry was new, so a re-seed that adds nothing does not
// force every worker to re-pull.
func (s *Store) SeedWorkloads(workloads map[string]pkgallowlist.Workload) (int, error) {
	if len(workloads) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	added, err := seedWorkloadsTx(tx, workloads)
	if err != nil {
		return 0, err
	}
	if added > 0 {
		if err := bumpVersionTx(tx); err != nil {
			return 0, err
		}
	}
	return added, s.commitTx(tx)
}

// seedWorkloadsTx inserts every entry whose name is free and returns how many
// it inserted.
func seedWorkloadsTx(tx *sql.Tx, workloads map[string]pkgallowlist.Workload) (int, error) {
	var added int
	for name, w := range workloads {
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM workload_entry WHERE name=?", name).Scan(&exists); err != nil {
			return 0, err
		}
		if exists != 0 {
			continue
		}
		entryJSON, err := json.Marshal(w)
		if err != nil {
			return 0, err
		}
		res, err := tx.Exec(
			"INSERT OR IGNORE INTO workload_entry (name, entry_json) VALUES (?, ?)",
			name, string(entryJSON),
		)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		if err := indexWorkloadTx(tx, name, w); err != nil {
			return 0, err
		}
		added++
	}
	return added, nil
}

// PutWorkload upserts one named workload entry and rebuilds its digest index in
// a single transaction, then bumps the version. The name and containers are
// validated against the frozen allowlist rules; a rejection wraps
// ErrInvalidWorkload.
func (s *Store) PutWorkload(name string, w pkgallowlist.Workload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	norm, err := normalizeEntry(name, w)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := putWorkloadTx(tx, name, norm); err != nil {
		return err
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}
	return s.commitTx(tx)
}

// DeleteWorkload removes one named entry and its index rows, bumping the version
// only when the entry existed. Returns false if absent.
func (s *Store) DeleteWorkload(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.Exec("DELETE FROM workload_entry WHERE name = ?", name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if _, err := tx.Exec("DELETE FROM workload_entry_digest WHERE entry_name = ?", name); err != nil {
		return false, err
	}
	if err := bumpVersionTx(tx); err != nil {
		return false, err
	}
	return true, s.commitTx(tx)
}

// ReplaceAll atomically swaps the entire allowlist for the given document and
// bumps the version. An empty document clears everything.
func (s *Store) ReplaceAll(al *pkgallowlist.Allowlist) error {
	if al == nil {
		return fmt.Errorf("allowlist is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := replaceContentsTx(tx, al); err != nil {
		return err
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}
	return s.commitTx(tx)
}

// replaceContentsTx clears every entry and reloads them from al, without
// touching the version. Callers set the version (bump or restore).
func replaceContentsTx(tx *sql.Tx, al *pkgallowlist.Allowlist) error {
	for _, stmt := range []string{
		"DELETE FROM workload_entry",
		"DELETE FROM workload_entry_digest",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	for name, w := range al.Workloads {
		entryJSON, err := json.Marshal(w)
		if err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO workload_entry (name, entry_json) VALUES (?, ?)", name, string(entryJSON)); err != nil {
			return err
		}
		if err := indexWorkloadTx(tx, name, w); err != nil {
			return err
		}
	}
	return nil
}

// putWorkloadTx upserts one entry's canonical JSON and rebuilds its index rows.
func putWorkloadTx(tx *sql.Tx, name string, w pkgallowlist.Workload) error {
	entryJSON, err := json.Marshal(w)
	if err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT OR REPLACE INTO workload_entry (name, entry_json) VALUES (?, ?)", name, string(entryJSON)); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM workload_entry_digest WHERE entry_name = ?", name); err != nil {
		return err
	}
	return indexWorkloadTx(tx, name, w)
}

// indexWorkloadTx writes one (digest, name, role) index row per container. A
// digest repeated within a role (same image, different argv) collapses to one
// row via the primary key.
func indexWorkloadTx(tx *sql.Tx, name string, w pkgallowlist.Workload) error {
	for _, part := range []struct {
		role string
		cs   []pkgallowlist.Container
	}{{roleInit, w.InitContainers}, {roleMain, w.Containers}} {
		for _, c := range part.cs {
			if _, err := tx.Exec(
				"INSERT OR IGNORE INTO workload_entry_digest (digest, entry_name, role) VALUES (?, ?, ?)",
				c.Digest.String(), name, part.role,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// normalizeEntry validates name and w through the allowlist validator and
// returns the canonical entry to store. A rejection wraps ErrInvalidWorkload.
func normalizeEntry(name string, w pkgallowlist.Workload) (pkgallowlist.Workload, error) {
	probe := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{name: w},
	}
	canon, err := probe.Canonical()
	if err != nil {
		return pkgallowlist.Workload{}, fmt.Errorf("%w: %v", ErrInvalidWorkload, err)
	}
	parsed, err := pkgallowlist.ParseJSON(canon)
	if err != nil {
		return pkgallowlist.Workload{}, fmt.Errorf("%w: %v", ErrInvalidWorkload, err)
	}
	return parsed.Workloads[name], nil
}
