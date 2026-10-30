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
// operator write token that wrote a document, and used_token the tokens
// already spent, each with its iat and exp in Unix seconds
// (docs/allowlist-and-capabilities.md, "Allowlist history").
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
	exp_unix INTEGER NOT NULL,
	iat_unix INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS used_token_exp ON used_token (exp_unix);
CREATE INDEX IF NOT EXISTS used_token_iat ON used_token (iat_unix);
`

// HistoryEntry is one document in the allowlist history, as GET
// /allowlist/history serves it.
type HistoryEntry struct {
	Position    int64     `json:"position"`
	Version     string    `json:"version"`
	Digest      string    `json:"digest"`
	PublishedAt time.Time `json:"published_at"`
	// Signed reports whether an operator signature is stored for Digest. It
	// describes the document, not this entry's write: a write that returns to
	// a document signed before shows it signed.
	Signed bool `json:"signed"`
}

// objectDigest is "sha256:<hex>" of b, the name history gives a document.
func objectDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// startJournal checks that every journaled document still hashes to its
// digest, then journals the document the store serves now if it is not
// already the head, so a fresh database starts its history with it. CDS calls
// it before serving; an error means the store is corrupt and CDS must not
// start.
func (s *Store) startJournal(at time.Time) error {
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
	if _, err := publishTx(tx, at); err != nil {
		return err
	}
	return tx.Commit()
}

// publishTx appends a history entry, timed at, for the document tx leaves in
// the store when its digest differs from the head's, and returns that
// document's canonical bytes.
func publishTx(tx *sql.Tx, at time.Time) ([]byte, error) {
	workloads, err := loadWorkloads(tx)
	if err != nil {
		return nil, err
	}
	body, err := (&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}).Canonical()
	if err != nil {
		return nil, err
	}
	digest := objectDigest(body)

	var head string
	var position int64
	err = tx.QueryRow("SELECT digest, position FROM journal_event ORDER BY position DESC LIMIT 1").Scan(&head, &position)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if head == digest {
		return body, nil
	}
	var version string
	if err := tx.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&version); err != nil {
		return nil, err
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO journal_object (digest, body) VALUES (?, ?)", digest, body); err != nil {
		return nil, err
	}
	if _, err := tx.Exec("INSERT INTO journal_event (position, version, digest, published_at_ms) VALUES (?, ?, ?, ?)",
		position+1, version, digest, at.UnixMilli()); err != nil {
		return nil, err
	}
	return body, nil
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
// digest are an error: the history was checked only at startup.
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

// documentSignature is an operator write token and the canonical document
// bytes its pbh claim binds. The zero value signs nothing: a seed carries no
// operator token.
type documentSignature struct {
	token    string
	document []byte
}

// storeTx records the signature of journaled, the document the write
// journaled. A journaled document that differs from the bytes the token binds
// fails the write: a signature must name what verifiers fetch.
func (s documentSignature) storeTx(tx *sql.Tx, journaled []byte) error {
	if s.token == "" {
		return nil
	}
	if !bytes.Equal(journaled, s.document) {
		return errors.New("the journaled allowlist is not the document the write signed")
	}
	_, err := tx.Exec("INSERT OR REPLACE INTO journal_signature (digest, token) VALUES (?, ?)", objectDigest(journaled), s.token)
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

// SpentTokenMargin is how long after the newest spent token's iat the record
// of an expired one is kept. It exceeds twice the operator JWT clock skew
// plus the clock difference between replicas, so no token the Verifier
// accepts is refused as one whose record may be gone.
const SpentTokenMargin = time.Hour

// consumeToken records that the JWT token authorized a request, or returns
// operatorauth.ErrTokenReused if it or another encoding of it already did:
// stored signatures make write tokens public.
//
// It drops the records of tokens that expired a margin before the highest iat
// spent, and refuses a token that old itself, so a pruned token stays spent.
// Claims are judged against claims, never a clock: every replica prunes the
// same rows, and a host that turns a clock back replays nothing.
func (s *Store) consumeToken(token string) error {
	iat, exp, err := operatorauth.UnverifiedTimes(token)
	if err != nil {
		return fmt.Errorf("spend operator token: %w", err)
	}
	digest := objectDigest([]byte(signedPart(token)))

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	watermark, err := spentWatermark(tx)
	if err != nil {
		return err
	}
	if exp.Unix() < prunedBefore(watermark) {
		return fmt.Errorf("%w: it expired over %s before the newest spent token was issued", operatorauth.ErrTokenReused, SpentTokenMargin)
	}
	res, err := tx.Exec(`
		INSERT OR IGNORE INTO used_token (digest, exp_unix, iat_unix)
		VALUES (?, ?, ?)`, digest, exp.Unix(), iat.Unix())
	if err != nil {
		return err
	}
	spends, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if spends == 0 {
		return operatorauth.ErrTokenReused
	}
	if _, err := tx.Exec(`
		DELETE FROM used_token
		WHERE exp_unix < ?`, prunedBefore(max(watermark, iat.Unix()))); err != nil {
		return err
	}
	return tx.Commit()
}

// signedPart is the token without its signature segment, which has several
// encodings that all verify (non-strict base64 padding bits, ECDSA (r, n-s)).
func signedPart(token string) string {
	if i := strings.LastIndexByte(token, '.'); i >= 0 {
		return token[:i]
	}
	return token
}

func spentWatermark(tx *sql.Tx) (int64, error) {
	var watermark int64
	err := tx.QueryRow("SELECT COALESCE(MAX(iat_unix), 0) FROM used_token").Scan(&watermark)
	return watermark, err
}

// prunedBefore is the exp (Unix seconds) below which a spent token's record
// may already be gone.
func prunedBefore(newestIAT int64) int64 {
	return newestIAT - int64(SpentTokenMargin/time.Second)
}

func (s *Store) HistoryLen() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM journal_event").Scan(&n)
	return n, err
}

// pruneHistory keeps the newest keep entries of the history and drops the
// documents and signatures no remaining entry names. It depends only on the
// store's contents, so every replica prunes the same entries.
func (s *Store) pruneHistory(keep int) error {
	if keep < 1 {
		return errors.New("allowlist: a history must keep at least one entry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var have int
	if err := tx.QueryRow("SELECT COUNT(*) FROM journal_event").Scan(&have); err != nil {
		return err
	}
	if have <= keep {
		return nil
	}
	if _, err := tx.Exec(`
		DELETE FROM journal_event
		WHERE position NOT IN (
			SELECT position FROM journal_event ORDER BY position DESC LIMIT ?
		)`, keep); err != nil {
		return err
	}
	for _, statement := range []string{
		`DELETE FROM journal_object
			WHERE digest NOT IN (SELECT digest FROM journal_event)`,
		`DELETE FROM journal_signature
			WHERE digest NOT IN (SELECT digest FROM journal_event)`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.gen++
	return nil
}

// LiveBytes is the store's pages less the free ones: what a replacement
// replica would copy, which the volume's used space overstates.
func (s *Store) LiveBytes() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	err := s.db.QueryRow(`
		SELECT (page_count - freelist_count) * page_size
		FROM pragma_page_count, pragma_freelist_count, pragma_page_size`).Scan(&n)
	return n, err
}

// HistoryKeepForBytes is how many of the newest history entries fit in budget
// bytes. Entries serving the same document cost those bytes once, and the
// newest entry is kept whatever its size.
func (s *Store) HistoryKeepForBytes(budget int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT e.digest, LENGTH(o.body)
		FROM journal_event e
		JOIN journal_object o ON o.digest = e.digest
		ORDER BY e.position DESC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	held := map[string]bool{}
	var bytes int64
	keep := 0
	for rows.Next() {
		var digest string
		var size int64
		if err := rows.Scan(&digest, &size); err != nil {
			return 0, err
		}
		if !held[digest] {
			if keep > 0 && bytes+size > budget {
				break
			}
			held[digest] = true
			bytes += size
		}
		keep++
	}
	return keep, rows.Err()
}
