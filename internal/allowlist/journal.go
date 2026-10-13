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
)

// The journal is the append-only history of every allowlist document CDS
// served: journal_object holds each document's canonical bytes under its
// digest, journal_event the order they were served in, journal_signature the
// operator write token of a whole-document PUT, and used_token the tokens
// already spent (docs/allowlist-and-capabilities.md, "Allowlist history").
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
CREATE TABLE IF NOT EXISTS journal_signature (
	digest TEXT PRIMARY KEY,
	token  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS used_token (
	digest   TEXT PRIMARY KEY,
	until_ms INTEGER NOT NULL
);
`

// HistoryEntry is one document in the allowlist history, as GET
// /allowlist/history serves it.
type HistoryEntry struct {
	Position    int64     `json:"position"`
	Version     string    `json:"version"`
	Digest      string    `json:"digest"`
	PublishedAt time.Time `json:"published_at"`
	// Signed reports whether an operator signature is stored for Digest.
	Signed bool `json:"signed"`
}

// ErrTokenReused refuses an operator token that already authorized a write.
var ErrTokenReused = errors.New("operator token already used")

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
func (s *Store) StartJournal() error {
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
	if err := publishTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// publishTx appends a history entry for the document tx leaves in the store
// when its digest differs from the head's.
func publishTx(tx *sql.Tx) error {
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
		position+1, version, digest, time.Now().UnixMilli())
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

// Object returns the canonical bytes of the journaled document digest
// ("sha256:<hex>"), or false when there is none.
func (s *Store) Object(digest string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b []byte
	err := s.db.QueryRow("SELECT body FROM journal_object WHERE digest = ?", digest).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return b, err == nil, err
}

// SignPolicy stores token, the operator write token that authorized a
// whole-document write of body, as the signature of that document. It stores
// nothing unless body is byte for byte a journaled document: the token's pbh
// claim binds body, so only then does it sign what verifiers fetch.
func (s *Store) SignPolicy(body []byte, token string) error {
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

// ConsumeToken records that the JWT token authorized a write, or returns
// ErrTokenReused if it or another encoding of it already did. Stored
// signatures make write tokens public, so each must authorize one write only.
// The record survives restarts of a persistent store and is pruned after
// until, when the token no longer verifies anyway.
func (s *Store) ConsumeToken(token string, until time.Time) error {
	// Key on the signed header.payload: the signature segment has several
	// encodings that all verify (non-strict base64 padding bits, ECDSA (r, n-s)).
	if i := strings.LastIndexByte(token, '.'); i >= 0 {
		token = token[:i]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("DELETE FROM used_token WHERE until_ms < ?", time.Now().UnixMilli()); err != nil {
		return err
	}
	res, err := s.db.Exec("INSERT OR IGNORE INTO used_token (digest, until_ms) VALUES (?, ?)", objectDigest([]byte(token)), until.UnixMilli())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTokenReused
	}
	return nil
}
