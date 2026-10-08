package allowlist

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Journal event types. See docs/allowlist-and-capabilities.md, "Rollout journal".
const (
	EventPublished = "published"
	EventDrained   = "drained"
)

const journalSQL = `
CREATE TABLE IF NOT EXISTS journal_object (
	digest TEXT PRIMARY KEY,
	body   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS journal_event (
	position INTEGER PRIMARY KEY,
	digest   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS journal_pending (
	target         TEXT NOT NULL,
	published_ms   INTEGER NOT NULL
);
`

// ErrUpdatePending rejects a write while a published update waits for
// activation.
var ErrUpdatePending = errors.New("an allowlist update is still activating")

// Event is one journal entry. Its canonical bytes are json.Marshal of the
// struct; Parent chains it to the previous event's digest.
type Event struct {
	Protocol      int    `json:"protocol"`
	Authority     string `json:"authority"`
	Position      uint64 `json:"position"`
	Parent        string `json:"parent,omitempty"`
	Type          string `json:"type"`
	Version       string `json:"allowlist_version"`
	Source        string `json:"source,omitempty"`
	Target        string `json:"target"`
	DrainRequired bool   `json:"drain_required,omitempty"`
}

// State is the unsigned rollout state CDS signs.
type State = types.RolloutState

func objectDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// StartJournal sets the authority fingerprint later events carry and, when the
// journal is empty, publishes the current document as its first event.
//
// A positive lease stages every later publication: the store keeps serving the
// source document until Activate runs lease after both the publication and
// this call. Routers fence their sessions on the same lease.
func (s *Store) StartJournal(authority string, lease time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authority, s.lease, s.started = authority, lease, time.Now()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := publishTx(tx, authority); err != nil {
		return err
	}
	return tx.Commit()
}

// journalTx runs before every mutation commits. It refuses the write while an
// update is pending, whatever the current lease, journals the new document
// and, under a lease, restores the source document and records the target as
// pending.
func (s *Store) journalTx(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM journal_pending").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrUpdatePending
	}
	source, err := publishTx(tx, s.authority)
	if err != nil || source == nil || s.lease <= 0 {
		return err
	}
	var prev pkgallowlist.Allowlist
	if err := json.Unmarshal(source, &prev); err != nil {
		return err
	}
	head, _, err := headTx(tx)
	if err != nil {
		return err
	}
	if err := replaceContentsTx(tx, &prev); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE allowlist_version SET version = CAST(CAST(version AS INTEGER) - 1 AS TEXT)"); err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO journal_pending (target, published_ms) VALUES (?, ?)", head.Target, time.Now().UnixMilli())
	return err
}

// Activate installs the pending target once the lease has run from both its
// publication and StartJournal, and reports whether it did.
func (s *Store) Activate(now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var target string
	var published int64
	err = tx.QueryRow("SELECT target, published_ms FROM journal_pending").Scan(&target, &published)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	since := time.UnixMilli(published)
	if s.started.After(since) {
		since = s.started
	}
	if now.Before(since.Add(s.lease)) {
		return false, nil
	}
	body, err := objectTx(tx, target)
	if err != nil {
		return false, err
	}
	var q pkgallowlist.Allowlist
	if err := json.Unmarshal(body, &q); err != nil {
		return false, err
	}
	if err := replaceContentsTx(tx, &q); err != nil {
		return false, err
	}
	if err := bumpVersionTx(tx); err != nil {
		return false, err
	}
	if _, err := tx.Exec("DELETE FROM journal_pending"); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	s.gen++
	return true, nil
}

// publishTx appends a published event when the document in tx differs from
// the journal head's target, and returns the source document's canonical
// bytes when it appended one with a source.
func publishTx(tx *sql.Tx, authority string) ([]byte, error) {
	workloads, err := loadWorkloadsTx(tx)
	if err != nil {
		return nil, err
	}
	q := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}
	qBytes, err := q.Canonical()
	if err != nil {
		return nil, err
	}
	var version string
	if err := tx.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&version); err != nil {
		return nil, err
	}

	head, headDigest, err := headTx(tx)
	if err != nil {
		return nil, err
	}
	qDigest := objectDigest(qBytes)
	ev := Event{Protocol: 1, Authority: authority, Type: EventPublished, Version: version, Target: qDigest}
	var pBytes []byte
	if head != nil {
		if head.Target == ev.Target {
			return nil, nil
		}
		if pBytes, err = objectTx(tx, head.Target); err != nil {
			return nil, err
		}
		ev.Position, ev.Parent, ev.Source = head.Position+1, headDigest, head.Target
		ev.DrainRequired = !covers(pBytes, q)
	}
	evBytes, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	evDigest := objectDigest(evBytes)
	for _, o := range []struct {
		digest string
		body   []byte
	}{{qDigest, qBytes}, {evDigest, evBytes}} {
		if _, err := tx.Exec("INSERT OR IGNORE INTO journal_object (digest, body) VALUES (?, ?)", o.digest, o.body); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec("INSERT INTO journal_event (position, digest) VALUES (?, ?)", ev.Position, evDigest); err != nil {
		return nil, err
	}
	return pBytes, nil
}

// covers reports whether q retains every workload entry of the canonical
// document p unchanged. Anything else is treated as a removal.
func covers(p []byte, q *pkgallowlist.Allowlist) bool {
	var prev pkgallowlist.Allowlist
	if err := json.Unmarshal(p, &prev); err != nil {
		return false
	}
	for name, pw := range prev.Workloads {
		qw, ok := q.Workloads[name]
		if !ok {
			return false
		}
		pj, err1 := json.Marshal(pw)
		qj, err2 := json.Marshal(qw)
		if err1 != nil || err2 != nil || !bytes.Equal(pj, qj) {
			return false
		}
	}
	return true
}

func headTx(tx *sql.Tx) (*Event, string, error) {
	var digest string
	err := tx.QueryRow("SELECT digest FROM journal_event ORDER BY position DESC LIMIT 1").Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	ev, err := eventTx(tx, digest)
	return ev, digest, err
}

func eventTx(tx *sql.Tx, digest string) (*Event, error) {
	b, err := objectTx(tx, digest)
	if err != nil {
		return nil, err
	}
	var ev Event
	if err := json.Unmarshal(b, &ev); err != nil {
		return nil, fmt.Errorf("decode journal event %s: %w", digest, err)
	}
	return &ev, nil
}

func objectTx(tx *sql.Tx, digest string) ([]byte, error) {
	var b []byte
	if err := tx.QueryRow("SELECT body FROM journal_object WHERE digest = ?", digest).Scan(&b); err != nil {
		return nil, fmt.Errorf("journal object %s: %w", digest, err)
	}
	return b, nil
}

// Object returns the canonical bytes stored under digest ("sha256:<hex>"),
// or false when there is none.
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

// State replays the journal into the current rollout state. The bound widens
// with every publication that requires draining and collapses to the target
// on a drained event or on a covering publication over a single policy.
func (s *Store) State() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil && s.stateGen == s.gen {
		return *s.state, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT e.digest, o.body FROM journal_event e
		JOIN journal_object o ON o.digest = e.digest ORDER BY e.position`)
	if err != nil {
		return State{}, err
	}
	defer rows.Close()

	st := State{Protocol: 1, Authority: s.authority, Lease: int64(s.lease / time.Second)}
	for rows.Next() {
		var d string
		var body []byte
		if err := rows.Scan(&d, &body); err != nil {
			return State{}, err
		}
		var ev Event
		if err := json.Unmarshal(body, &ev); err != nil {
			return State{}, fmt.Errorf("decode journal event %s: %w", d, err)
		}
		switch {
		case ev.Type == EventDrained, !ev.DrainRequired && len(st.Bound) <= 1:
			st.Bound = []string{ev.Target}
		case slices.Contains(st.Bound, ev.Target):
		default:
			st.Bound = append(st.Bound, ev.Target)
		}
		st.Position, st.Head, st.Version, st.Policy = ev.Position, d, ev.Version, ev.Target
	}
	if err := rows.Err(); err != nil {
		return State{}, err
	}
	if st.Head == "" {
		return State{}, errors.New("journal is empty")
	}
	if err := tx.QueryRow("SELECT target FROM journal_pending").Scan(&st.Pending); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return State{}, err
	}
	s.state, s.stateGen = &st, s.gen
	return st, nil
}
