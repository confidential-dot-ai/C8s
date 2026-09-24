package allowlist

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
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
`

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

// State is the unsigned rollout state CDS signs. Bound lists the policy
// digests that may still be executing, oldest first.
type State struct {
	Protocol  int      `json:"protocol"`
	Authority string   `json:"authority"`
	Position  uint64   `json:"position"`
	Head      string   `json:"head"`
	Version   string   `json:"allowlist_version"`
	Policy    string   `json:"policy"`
	Bound     []string `json:"bound"`
	Nonce     string   `json:"nonce,omitempty"`
}

func objectDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// StartJournal sets the authority fingerprint later events carry and, when the
// journal is empty, publishes the current document as its first event.
func (s *Store) StartJournal(authority string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authority = authority

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := publishTx(tx, authority); err != nil {
		return err
	}
	return tx.Commit()
}

// publishTx appends a published event when the document in tx differs from
// the journal head's target. Every mutation runs it before commit.
func publishTx(tx *sql.Tx, authority string) error {
	workloads, err := loadWorkloadsTx(tx)
	if err != nil {
		return err
	}
	q := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}
	qBytes, err := q.Canonical()
	if err != nil {
		return err
	}
	var version string
	if err := tx.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&version); err != nil {
		return err
	}

	head, headDigest, err := headTx(tx)
	if err != nil {
		return err
	}
	ev := Event{Protocol: 1, Authority: authority, Type: EventPublished, Version: version, Target: objectDigest(qBytes)}
	if head != nil {
		if head.Target == ev.Target {
			return nil
		}
		pBytes, err := objectTx(tx, head.Target)
		if err != nil {
			return err
		}
		ev.Position, ev.Parent, ev.Source = head.Position+1, headDigest, head.Target
		ev.DrainRequired = !covers(pBytes, q)
	}
	evBytes, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	for _, b := range [][]byte{qBytes, evBytes} {
		if _, err := tx.Exec("INSERT OR IGNORE INTO journal_object (digest, body) VALUES (?, ?)", objectDigest(b), b); err != nil {
			return err
		}
	}
	_, err = tx.Exec("INSERT INTO journal_event (position, digest) VALUES (?, ?)", ev.Position, objectDigest(evBytes))
	return err
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

	tx, err := s.db.Begin()
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback()

	rows, err := tx.Query("SELECT digest FROM journal_event ORDER BY position")
	if err != nil {
		return State{}, err
	}
	var digests []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return State{}, err
		}
		digests = append(digests, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return State{}, err
	}
	if len(digests) == 0 {
		return State{}, errors.New("journal is empty")
	}

	st := State{Protocol: 1, Authority: s.authority}
	for _, d := range digests {
		ev, err := eventTx(tx, d)
		if err != nil {
			return State{}, err
		}
		switch {
		case ev.Type == EventDrained, !ev.DrainRequired && len(st.Bound) <= 1:
			st.Bound = []string{ev.Target}
		default:
			st.Bound = append(st.Bound, ev.Target)
		}
		st.Position, st.Head, st.Version, st.Policy = ev.Position, d, ev.Version, ev.Target
	}
	return st, nil
}
