package allowlist

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The journal is the append-only history of every allowlist document CDS
// served: journal_object holds each document's canonical bytes under its
// digest, journal_event the order they were served in, journal_signature the
// operator write token of a whole-document PUT, and used_token the tokens
// already spent (docs/allowlist-and-capabilities.md, "Allowlist history"),
// with each one's iat and exp in Unix seconds (0 when not recorded).
const journalSQL = `
CREATE TABLE IF NOT EXISTS journal_object (
	digest TEXT PRIMARY KEY,
	body   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS journal_event (
	position        INTEGER PRIMARY KEY,
	version         TEXT NOT NULL,
	digest          TEXT NOT NULL,
	published_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS journal_event_digest ON journal_event (digest);
CREATE TABLE IF NOT EXISTS journal_signature (
	digest TEXT PRIMARY KEY,
	token  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS used_token (
	digest   TEXT PRIMARY KEY,
	exp_unix INTEGER NOT NULL DEFAULT 0,
	iat_unix INTEGER NOT NULL DEFAULT 0
);
`

// usedTokenColumns are the used_token columns later releases added, which a
// database created earlier lacks.
var usedTokenColumns = []string{"exp_unix", "iat_unix"}

// migrateJournal brings a database created by an earlier release to
// journalSQL: it adds the used_token columns it lacks (rows it held keep 0,
// which is never pruned) and their indexes.
func migrateJournal(db *sql.DB) error {
	rows, err := db.Query("SELECT name FROM pragma_table_info('used_token')")
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range usedTokenColumns {
		if have[c] {
			continue
		}
		if _, err := db.Exec("ALTER TABLE used_token ADD COLUMN " + c + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("add used_token.%s: %w", c, err)
		}
	}
	_, err = db.Exec(`
CREATE INDEX IF NOT EXISTS used_token_exp ON used_token (exp_unix);
CREATE INDEX IF NOT EXISTS used_token_iat ON used_token (iat_unix);
`)
	return err
}

// HistoryEntry is one document in the allowlist history, as GET
// /allowlist/history serves it.
type HistoryEntry struct {
	Position    int64     `json:"position"`
	Version     string    `json:"version"`
	Digest      string    `json:"digest"`
	PublishedAt time.Time `json:"published_at"`
	// Signed reports whether an operator signature is stored for Digest. It
	// describes the document, not this entry's write: a per-workload write that
	// returns to a signed document shows it signed.
	Signed bool `json:"signed"`
}

// ErrUnavailable wraps a replication failure: an HA replica that has no
// leader or lost its quorum could not commit the write (or the token spend
// before it). It is retryable, so handlers answer 503.
var ErrUnavailable = errors.New("allowlist: replicated store unavailable (no leader or no quorum); retry")

// objectDigest is "sha256:<hex>" of b, the name history gives a document.
func objectDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// StartJournal checks that every journaled document still hashes to its
// digest, then journals the document the store serves now if it is not
// already the head, so a fresh database starts its history with it. CDS calls
// it before serving; an error means the store is corrupt and CDS must not
// start.
func (s *Store) startJournal() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT e.position, e.digest, o.body FROM journal_event e
		LEFT JOIN journal_object o ON o.digest = e.digest ORDER BY e.position`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var position int64
		var digest string
		var body []byte
		if err := rows.Scan(&position, &digest, &body); err != nil {
			return err
		}
		if body == nil {
			return fmt.Errorf("allowlist history position %d: object %s is missing", position, digest)
		}
		if objectDigest(body) != digest {
			return fmt.Errorf("allowlist history position %d: object does not hash to %s", position, digest)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := publishTx(tx, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

// publishTx appends a history entry for the document tx leaves in the store
// when its digest differs from the head's.
func publishTx(tx *sql.Tx, now time.Time) error {
	workloads, err := loadWorkloads(tx)
	if err != nil {
		return err
	}
	body, err := (&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}).Canonical()
	if err != nil {
		return err
	}
	digest := objectDigest(body)

	var head string
	var position int64
	err = tx.QueryRow("SELECT digest, position FROM journal_event ORDER BY position DESC LIMIT 1").Scan(&head, &position)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if head == digest {
		return nil
	}
	var version string
	if err := tx.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&version); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO journal_object (digest, body) VALUES (?, ?)", digest, body); err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO journal_event (position, version, digest, published_at_ms) VALUES (?, ?, ?, ?)",
		position+1, version, digest, now.UnixMilli())
	return err
}

// History returns every document the store has served, oldest first.
func (s *Store) History() ([]HistoryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT e.position, e.version, e.digest, e.published_at_ms, s.digest IS NOT NULL
		FROM journal_event e LEFT JOIN journal_signature s ON s.digest = e.digest ORDER BY e.position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []HistoryEntry{}
	for rows.Next() {
		var e HistoryEntry
		var ms int64
		if err := rows.Scan(&e.Position, &e.Version, &e.Digest, &ms, &e.Signed); err != nil {
			return nil, err
		}
		e.PublishedAt = time.UnixMilli(ms).UTC()
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Object returns the canonical bytes of the document digest ("sha256:<hex>")
// in the history, or false when there is none. Bytes that no longer hash to
// digest are an error: StartJournal checked them only at startup.
func (s *Store) Object(digest string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b []byte
	err := s.db.QueryRow(`SELECT body FROM journal_object WHERE digest = ?
		AND EXISTS (SELECT 1 FROM journal_event WHERE digest = ?)`, digest, digest).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if objectDigest(b) != digest {
		return nil, false, fmt.Errorf("allowlist history object does not hash to %s", digest)
	}
	return b, true, nil
}

// SignPolicy stores token, the operator write token that authorized a
// whole-document write of body, as the signature of that document. It stores
// nothing unless body is byte for byte a journaled document: the token's pbh
// claim binds body, so only then does it sign what verifiers fetch.
func (s *Store) signPolicy(body []byte, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest := objectDigest(body)
	var stored []byte
	err := s.db.QueryRow("SELECT body FROM journal_object WHERE digest = ?", digest).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !bytes.Equal(stored, body)) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT OR REPLACE INTO journal_signature (digest, token) VALUES (?, ?)", digest, token)
	return err
}

// Signature returns the operator write token stored for digest, or false when
// the document is unsigned.
func (s *Store) Signature(digest string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var token string
	err := s.db.QueryRow("SELECT token FROM journal_signature WHERE digest = ?", digest).Scan(&token)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return token, err == nil, err
}

// spentTokenMargin is how long after the newest spent token's iat CDS keeps
// the record of an expired one. Pruning compares two operator-signed claims,
// never a clock, so every replica prunes the same rows: consumeToken drops
// the records of tokens whose exp is more than spentTokenMargin before the
// highest iat spent so far (the watermark), and refuses any later token in
// that range itself, so a pruned token stays spent even under a clock the
// host turned back.
//
// The margin only has to keep that refusal away from tokens the Verifier
// accepts. A token the Verifier accepts now has exp >= now - skew, and the
// watermark was accepted earlier, so iat <= now + skew (on another replica,
// plus the clock difference between the two). 2 x skew plus the replicas'
// clock difference must therefore stay below the margin: an hour covers
// --jwt-clock-skew (Helm cds.jwtClockSkew, 30 s by default) up to about 25
// minutes with replicas minutes apart. A larger skew only refuses (409) a
// token issued that long before the newest one; nothing becomes replayable.
// The table keeps the tokens spent in the last margin plus MaxTokenValidity.
const spentTokenMargin = time.Hour

// ConsumeToken records that the JWT token authorized a request, or returns
// operatorauth.ErrTokenReused if it or another encoding of it already did. Stored
// signatures make write tokens public, so each must authorize one request only.
//
// With expiry (every store from cdsha.Format 2; a replicated group of an
// earlier format leaves it off so it agrees with replicas that predate it),
// it also records the token's iat and exp and prunes by spentTokenMargin.
// A token whose claims do not parse is recorded with 0s and kept, and
// prunes nothing. Records written without expiry are kept too.
func (s *Store) consumeToken(token string, expiry bool) error {
	var iat, exp int64
	if expiry {
		if i, e, err := operatorauth.UnverifiedTimes(token); err == nil {
			iat, exp = i.Unix(), e.Unix()
			if e.Nanosecond() != 0 {
				exp++ // round exp up and iat down: either keeps a record longer
			}
		}
	}
	// Key on the signed header.payload: the signature segment has several
	// encodings that all verify (non-strict base64 padding bits, ECDSA (r, n-s)).
	if i := strings.LastIndexByte(token, '.'); i >= 0 {
		token = token[:i]
	}
	digest := objectDigest([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp == 0 {
		res, err := s.db.Exec("INSERT OR IGNORE INTO used_token (digest) VALUES (?)", digest)
		if err != nil {
			return err
		}
		return spentUnlessInserted(res)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var watermark int64
	if err := tx.QueryRow("SELECT COALESCE(MAX(iat_unix), 0) FROM used_token").Scan(&watermark); err != nil {
		return err
	}
	margin := int64(spentTokenMargin / time.Second)
	if exp < watermark-margin {
		// Its record may be pruned: only this refusal keeps it spent.
		return fmt.Errorf("%w: it expired over %s before the newest spent token was issued", operatorauth.ErrTokenReused, spentTokenMargin)
	}
	res, err := tx.Exec("INSERT OR IGNORE INTO used_token (digest, exp_unix, iat_unix) VALUES (?, ?, ?)", digest, exp, iat)
	if err != nil {
		return err
	}
	if err := spentUnlessInserted(res); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM used_token WHERE exp_unix > 0 AND exp_unix < ?", max(watermark, iat)-margin); err != nil {
		return err
	}
	return tx.Commit()
}

func spentUnlessInserted(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return operatorauth.ErrTokenReused
	}
	return nil
}

// HistoryLen is the number of entries in the history.
func (s *Store) HistoryLen() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM journal_event").Scan(&n)
	return n, err
}

// pruneHistory keeps the newest keep entries of the history and drops the
// documents and signatures no remaining entry names. The served document is
// the head, which always remains, and spent tokens are left to consumeToken
// (a token must never be spendable again). It depends only on the store's contents, so
// every replica applying it prunes the same entries.
func (s *Store) pruneHistory(keep int) (int, error) {
	if keep < 1 {
		return 0, errors.New("allowlist: a history must keep at least one entry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var head int64
	if err := tx.QueryRow("SELECT COALESCE(MAX(position), 0) FROM journal_event").Scan(&head); err != nil {
		return 0, err
	}
	res, err := tx.Exec("DELETE FROM journal_event WHERE position <= ?", head-int64(keep))
	if err != nil {
		return 0, err
	}
	dropped, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if dropped == 0 {
		return 0, nil
	}
	for _, q := range []string{
		"DELETE FROM journal_object WHERE digest NOT IN (SELECT digest FROM journal_event)",
		"DELETE FROM journal_signature WHERE digest NOT IN (SELECT digest FROM journal_event)",
	} {
		if _, err := tx.Exec(q); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.gen++
	return int(dropped), nil
}

// PruneHistory keeps the newest keep entries of the history (see
// pruneHistory); with a replicator, every replica prunes through the log.
func (s *Store) PruneHistory(keep int) (int, error) {
	if s.repl == nil {
		return s.pruneHistory(keep)
	}
	res, err := s.replicate(Command{Op: OpPruneHistory, Keep: keep})
	return res.Retired, err
}

// LiveBytes is the space the store's data takes: its pages less the free
// ones. A pruned history frees pages SQLite reuses but does not return to the
// filesystem, so the volume's used space overstates what a replacement
// replica would have to copy; this does not.
func (s *Store) LiveBytes() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pageSize, pages, free int64
	for q, v := range map[string]*int64{"PRAGMA page_size": &pageSize, "PRAGMA page_count": &pages, "PRAGMA freelist_count": &free} {
		if err := s.db.QueryRow(q).Scan(v); err != nil {
			return 0, err
		}
	}
	return (pages - free) * pageSize, nil
}

// HistoryKeepForBytes is how many of the newest history entries fit in
// budget bytes of distinct documents (at least one: the served document).
func (s *Store) HistoryKeepForBytes(budget int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT e.digest, LENGTH(o.body) FROM journal_event e
		JOIN journal_object o ON o.digest = e.digest ORDER BY e.position DESC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var total int64
	keep := 0
	for rows.Next() {
		var digest string
		var size int64
		if err := rows.Scan(&digest, &size); err != nil {
			return 0, err
		}
		if !seen[digest] {
			seen[digest] = true
			total += size
		}
		if total > budget && keep > 0 {
			break
		}
		keep++
	}
	return keep, rows.Err()
}
