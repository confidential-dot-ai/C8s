package allowlist

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
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
// ETag). The journal tables (journal.go) keep the history of served documents.
// `route_manifest` holds the signed route manifest, which shares the database
// and so its lifetime (route policy C5).
type Store struct {
	mu sync.Mutex
	db *sql.DB
	// uri names the database for Restore, which opens its own connection.
	uri string
	// gen counts committed mutations in this process. It is the invalidation
	// signal for a reader that memoizes a whole-document snapshot
	// (internal/cmds/cds).
	gen uint64
	// Kept current by every write (digest.go).
	dig *contentDigest
}

// roleInit / roleMain label the two container partitions in the digest index.
const (
	roleInit = "init"
	roleMain = "main"
)

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
CREATE TABLE IF NOT EXISTS route_manifest (
	id       INTEGER PRIMARY KEY CHECK (id = 1),
	revision INTEGER NOT NULL,
	digest   TEXT NOT NULL,
	manifest BLOB NOT NULL,
	token    TEXT NOT NULL
);
`

// OpenStore opens (or creates) a SQLite-backed allowlist store at the given path.
func OpenStore(path string) (*Store, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		slog.Warn("allowlist db did not exist, creating", "path", path)
	}
	return open(path)
}

// OpenInMemory opens an in-memory allowlist store, useful for testing.
func OpenInMemory() (*Store, error) {
	return open(memdbURI("store"))
}

// open opens the database uri names and creates the tables it lacks.
func open(uri string) (*Store, error) {
	dig := &contentDigest{}
	db, err := dig.openDB(uri)
	if err != nil {
		return nil, fmt.Errorf("open allowlist db: %w", err)
	}
	if err := requireSpentTokenWindow(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("open allowlist db: %w", err)
	}
	if _, err := db.Exec(initSQL + journalSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("init allowlist schema: %w", err)
	}
	acc, err := scanDigest(context.Background(), db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("allowlist content digest: %w", err)
	}
	dig.startsFrom(acc)
	return &Store{
		db:  db,
		uri: uri,
		dig: dig,
	}, nil
}

// requireSpentTokenWindow refuses a database whose used_token table predates
// the validity window every spent token records.
func requireSpentTokenWindow(db *sql.DB) error {
	var columns, window int
	if err := db.QueryRow(`
		SELECT COUNT(*), COUNT(CASE WHEN name IN ('exp_unix', 'iat_unix') THEN 1 END)
		FROM pragma_table_info('used_token')`).Scan(&columns, &window); err != nil {
		return err
	}
	if columns > 0 && window != 2 {
		return errors.New("spent operator tokens have no validity window: delete the store and apply the allowlist again")
	}
	return nil
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

	workloads, err := loadWorkloads(s.db)
	if err != nil {
		return nil, "", err
	}

	return &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: workloads,
	}, version, nil
}

// querier is *sql.DB or *sql.Tx. Inside a transaction reads must go through
// the tx: an in-memory database is per connection.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func loadWorkloads(q querier) (map[string]pkgallowlist.Workload, error) {
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
// container image (docs/armtls.md).
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

// commitTx journals the document tx leaves at the command's time (see
// publishTx), stores sig as that document's operator signature, commits, and
// records the mutation for snapshot-cache invalidation. Every write path goes
// through it. Callers must hold s.mu.
func (s *Store) commitTx(tx *sql.Tx, sig documentSignature, at time.Time) error {
	journaled, err := publishTx(tx, at)
	if err != nil {
		return fmt.Errorf("journal allowlist: %w", err)
	}
	if err := sig.storeTx(tx, journaled); err != nil {
		return fmt.Errorf("sign allowlist: %w", err)
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

// RaiseVersion sets the version to the larger of the next version and floor,
// and returns it: a cluster passing its start time in Unix ms stays above
// every version an earlier life of it served. Nothing is journaled.
func (s *Store) RaiseVersion(floor int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var served int64
	if err := tx.QueryRow("SELECT CAST(version AS INTEGER) FROM allowlist_version").Scan(&served); err != nil {
		return "", fmt.Errorf("raise allowlist version: %w", err)
	}
	raised := strconv.FormatInt(max(served+1, floor), 10)
	if _, err := tx.Exec("UPDATE allowlist_version SET version = ?", raised); err != nil {
		return "", fmt.Errorf("raise allowlist version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.gen++
	return raised, nil
}

// seedWorkloads adds every workload entry whose name is not already present
// and retires each stored entry the seed replaces (retiredBySeed), in a single
// transaction, and returns the numbers added and retired. Additive for
// everything else and idempotent: an existing entry is left untouched and the
// version is bumped at most once, only when the set changed, so a re-seed that
// changes nothing does not force every worker to re-pull.
func (s *Store) seedWorkloads(workloads map[string]pkgallowlist.Workload, at time.Time) (added, retired int, err error) {
	if len(workloads) == 0 {
		return 0, 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	if retired, err = retireReplacedTx(tx, workloads); err != nil {
		return 0, 0, err
	}
	if added, err = seedWorkloadsTx(tx, workloads); err != nil {
		return 0, 0, err
	}
	if added+retired > 0 {
		if err := bumpVersionTx(tx); err != nil {
			return 0, 0, err
		}
	}
	return added, retired, s.commitTx(tx, documentSignature{}, at)
}

// retireReplacedTx deletes every stored entry seed replaces and returns how
// many it deleted.
func retireReplacedTx(tx *sql.Tx, seed map[string]pkgallowlist.Workload) (int, error) {
	seedKeys, overrideKeys := map[string]bool{}, map[string]bool{}
	for name := range seed {
		if key := GeneratedKey(name); key != "" {
			seedKeys[key] = true
		}
		if key := overrideKey(name); key != "" {
			overrideKeys[key] = true
		}
	}
	stored, err := loadWorkloads(tx)
	if err != nil {
		return 0, err
	}
	var retired int
	for name, w := range stored {
		// An override takes its name from the <image>-<12 hex> entry releases
		// before per-shape names generated, which the store may still hold.
		if entry, ok := seed[name]; ok && (overrideKey(name) == "" || sameWorkload(entry, w)) {
			continue
		}
		if !retiredBySeed(name, w, seedKeys, overrideKeys) {
			continue
		}
		if _, err := tx.Exec("DELETE FROM workload_entry WHERE name = ?", name); err != nil {
			return 0, err
		}
		if _, err := tx.Exec("DELETE FROM workload_entry_digest WHERE entry_name = ?", name); err != nil {
			return 0, err
		}
		slog.Info("allowlist seed retired a replaced entry", "workload", name)
		retired++
	}
	return retired, nil
}

func sameWorkload(a, b pkgallowlist.Workload) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && bytes.Equal(x, y)
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

// ErrVersionMismatch refuses a conditional whole-document write: the
// allowlist is no longer at the version the write names.
var ErrVersionMismatch = errors.New("the allowlist changed since it was read (If-Match names an older version)")

// OperatorWrite is what an operator's whole-document write carries beside the
// document itself.
type OperatorWrite struct {
	// Version, when set, is the write's precondition: the document is
	// replaced only while the store is at that version.
	Version string `json:"version,omitempty"`
	// Signature, when set, is the write token whose body hash binds the
	// document's canonical bytes, stored as that document's signature.
	Signature string `json:"signature,omitempty"`
}

// replaceAll atomically swaps the entire allowlist for the given document and
// bumps the version. An empty document clears everything. A write whose
// Version the store is no longer at returns ErrVersionMismatch and changes
// nothing; a write with a Signature stores it with the document, so a signed
// write never serves its document unsigned.
func (s *Store) replaceAll(al *pkgallowlist.Allowlist, write OperatorWrite, at time.Time) error {
	if al == nil {
		return fmt.Errorf("allowlist is required")
	}
	signed, err := al.Canonical()
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := requireVersionTx(tx, write.Version); err != nil {
		return err
	}
	if err := replaceContentsTx(tx, al); err != nil {
		return err
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}
	return s.commitTx(
		tx,
		documentSignature{
			token:    write.Signature,
			document: signed,
		},
		at,
	)
}

// requireVersionTx returns ErrVersionMismatch unless the store is at version,
// read in the transaction that writes; an empty version writes
// unconditionally.
func requireVersionTx(tx *sql.Tx, version string) error {
	if version == "" {
		return nil
	}
	var stored string
	if err := tx.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&stored); err != nil {
		return fmt.Errorf("read allowlist version: %w", err)
	}
	if stored != version {
		return ErrVersionMismatch
	}
	return nil
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
