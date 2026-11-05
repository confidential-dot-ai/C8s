package metadatapilot

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

const (
	StateReadPath       = "/v1/state/read"
	StateCommitPath     = "/v1/state/commit"
	MaxTransactionKeys  = 16
	MaxTransactionBytes = 2 << 20
)

// Record holds an opaque current value, not a command to replay. Keys are
// keyed hashes, values are encrypted by CDS, and versions are monotonically increasing per-record counters.
// An absent record has an empty version and value. Records are never deleted
// by this pilot, so an absence cannot be manufactured by a delete/recreate ABA.
type Record struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	Value   []byte `json:"value,omitempty"`
}

type Check struct {
	Key     string `json:"key"`
	Version string `json:"version"`
}

// Transaction commits only if EVERY read version still matches. Checks that
// are read-only do not change version: independent secret writes may share a
// policy predicate without writing one global commit head.
type Transaction struct {
	Checks []Check  `json:"checks"`
	Writes []Record `json:"writes,omitempty"`
}

func digestString(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// NextVersion is also enforced by the service. A client that knows storage
// credentials cannot reinstall a previously authenticated ciphertext/version
// pair. Whole-database rollback remains outside this trusted-service contract.
func NextVersion(old string) (string, error) {
	var n uint64
	if old != "" {
		var err error
		n, err = strconv.ParseUint(old, 16, 64)
		if err != nil || n == 0 || fmt.Sprintf("%016x", n) != old || n == ^uint64(0) {
			return "", errors.New("metadata: invalid or exhausted record version")
		}
	}
	return fmt.Sprintf("%016x", n+1), nil
}

func validVersion(v string) bool {
	n, err := strconv.ParseUint(v, 16, 64)
	return err == nil && n != 0 && fmt.Sprintf("%016x", n) == v
}

func (t Transaction) Check(read bool) error {
	bad := errors.New("metadata: invalid state transaction")
	if len(t.Checks) == 0 || len(t.Checks) > MaxTransactionKeys || len(t.Writes) > len(t.Checks) || (read && len(t.Writes) != 0) || (!read && len(t.Writes) == 0) {
		return bad
	}
	keys := make(map[string]string, len(t.Checks))
	for _, c := range t.Checks {
		if _, exists := keys[c.Key]; exists || !digestString(c.Key) || (c.Version != "" && !validVersion(c.Version)) || (read && c.Version != "") {
			return bad
		}
		keys[c.Key] = c.Version
	}
	seen := make(map[string]bool, len(t.Writes))
	for _, w := range t.Writes {
		old, exists := keys[w.Key]
		next, err := NextVersion(old)
		if !exists || seen[w.Key] || err != nil || w.Version != next || len(w.Value) == 0 || len(w.Value) > MaxHeadBytes {
			return bad
		}
		seen[w.Key] = true
	}
	return nil
}

func readTransaction(r io.Reader) (Transaction, error) {
	var t Transaction
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&t); err != nil {
		return t, err
	}
	if _, err := d.Token(); err != io.EOF {
		return t, errors.New("multiple transaction values")
	}
	return t, nil
}

// The existing per-cluster actor owns short SQLite transactions only. Object
// uploads, decryption, application work and backoff never run in this actor.
// SQLite FULL synchronous is the local durability oracle, not a replicated
// metadata implementation. A production adapter needs strict serializability.
func (s *Service) executeState(c command) result {
	failed := result{status: http.StatusServiceUnavailable}
	tx, err := s.db.BeginTx(c.ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return failed
	}
	defer tx.Rollback()
	rows := make([]Record, 0, len(c.state.Checks))
	for _, check := range c.state.Checks {
		r := Record{Key: check.Key}
		err := tx.QueryRowContext(c.ctx, `SELECT version,value FROM current_state WHERE key=?`, r.Key).Scan(&r.Version, &r.Value)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return failed
		}
		if c.write && r.Version != check.Version {
			s.conflicts.Add(1)
			return result{status: http.StatusPreconditionFailed}
		}
		rows = append(rows, r)
	}
	if !c.write {
		s.reads.Add(1)
		body, err := json.Marshal(rows)
		if err != nil {
			return failed
		}
		return result{status: http.StatusOK, value: body}
	}
	s.writes.Add(1)
	for _, r := range c.state.Writes {
		if _, err := tx.ExecContext(c.ctx, `INSERT INTO current_state(key,version,value) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET version=excluded.version,value=excluded.value`, r.Key, r.Version, r.Value); err != nil {
			return failed
		}
	}
	if err := tx.Commit(); err != nil {
		return failed
	}
	s.commits.Add(1)
	return result{status: http.StatusNoContent}
}

// Read returns one strictly consistent snapshot of exactly the requested keys.
func (c *Client) Read(ctx context.Context, keys []string) ([]Record, error) {
	t := Transaction{}
	for _, key := range keys {
		t.Checks = append(t.Checks, Check{Key: key})
	}
	body, err := c.stateRequest(ctx, t, true)
	if err != nil {
		return nil, err
	}
	var rows []Record
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != len(keys) {
		return nil, objectwal.ErrCorrupt
	}
	for i, r := range rows {
		if r.Key != keys[i] || (r.Version == "" && len(r.Value) != 0) || (r.Version != "" && (!validVersion(r.Version) || len(r.Value) == 0 || len(r.Value) > MaxHeadBytes)) {
			return nil, objectwal.ErrCorrupt
		}
	}
	return rows, nil
}

// Commit sends a conditional transaction ONCE. Only 412 proves it did not
// commit. A lost response or any ambiguous failure is ErrInDoubt; the caller
// must read current state before deciding whether a new operation is safe.
func (c *Client) Commit(ctx context.Context, t Transaction) error {
	_, err := c.stateRequest(ctx, t, false)
	return err
}

func (c *Client) stateRequest(ctx context.Context, t Transaction, read bool) ([]byte, error) {
	if err := t.Check(read); err != nil {
		return nil, err
	}
	body, err := json.Marshal(t)
	if err != nil || len(body) > MaxTransactionBytes {
		return nil, errors.New("metadata: transaction too large")
	}
	path := StateCommitPath
	if read {
		path = StateReadPath
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+*c.token.Load())
	r.Header.Set("X-CDS-Namespace", c.namespace)
	r.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(r)
	if err != nil {
		if !read {
			return nil, objectwal.ErrInDoubt
		}
		return nil, errors.New("metadata: state read transport failed")
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusPreconditionFailed:
		return nil, objectwal.ErrConflict
	case http.StatusTooManyRequests:
		return nil, objectwal.ErrBackpressure
	}
	want := http.StatusNoContent
	if read {
		want = http.StatusOK
	}
	if response.StatusCode != want {
		if !read {
			return nil, objectwal.ErrInDoubt
		}
		return nil, errors.New("metadata: state read failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxTransactionBytes+1))
	if err != nil || len(data) > MaxTransactionBytes {
		if !read {
			return nil, objectwal.ErrInDoubt
		}
		return nil, errors.New("metadata: invalid state response")
	}
	return data, nil
}
