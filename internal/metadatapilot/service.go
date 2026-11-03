// Package metadatapilot implements the local transactional-metadata comparison
// arm. It stores opaque encrypted heads; it never receives a CDS encryption key.
// SQLite supplies durable transactions on one machine, not replicated HA.
package metadatapilot

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	MaxHeadBytes = 64 << 10
	Capacity     = 64 // HTTP admission and the actor mailbox each have this bound.
	HeadPath     = "/v1/head"
)

type command struct {
	ctx      context.Context
	write    bool
	expected string
	value    []byte
	reply    chan result
}

type result struct {
	value  []byte
	etag   string
	status int
}

type Stats struct {
	Reads     uint64 `json:"reads"`
	Writes    uint64 `json:"writes"`
	Commits   uint64 `json:"commits"`
	Conflicts uint64 `json:"conflicts"`
	Rejected  uint64 `json:"rejected"`
	Admitted  int    `json:"admitted"` // Active HTTP handlers, including body reads and replies.
}

// One actor owns the database and all transactions. HTTP admission is bounded
// before body allocation. There is no application mutex across database IO.
type Service struct {
	namespace string
	token     [32]byte
	db        *sql.DB
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	inbox     chan command
	slots     chan struct{}
	reads     atomic.Uint64
	writes    atomic.Uint64
	commits   atomic.Uint64
	conflicts atomic.Uint64
	rejected  atomic.Uint64
}

func Open(path, namespace, token string) (*Service, error) {
	if path == "" || path == ":memory:" || strings.Contains(path, "?") || !validNamespace(namespace) || !ValidToken(token) {
		return nil, errors.New("metadata pilot: persistent file, namespace and separate bearer token required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	good := false
	defer func() {
		if !good {
			db.Close()
		}
	}()
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;
CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), namespace TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS head (id INTEGER PRIMARY KEY CHECK(id=1), etag TEXT NOT NULL, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS receipts (etag TEXT PRIMARY KEY, previous TEXT NOT NULL, digest BLOB NOT NULL);`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO identity(id,namespace) VALUES(1,?)`, namespace); err != nil {
		return nil, err
	}
	var identity, mode string
	var synchronous int
	if err := db.QueryRow(`SELECT namespace FROM identity WHERE id=1`).Scan(&identity); err != nil {
		return nil, err
	}
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		return nil, err
	}
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		return nil, err
	}
	if identity != namespace || mode != "wal" || synchronous != 2 {
		return nil, errors.New("metadata pilot: namespace or durable SQLite settings mismatch")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{namespace: namespace, token: sha256.Sum256([]byte(token)), db: db, ctx: ctx, cancel: cancel,
		done: make(chan struct{}), inbox: make(chan command, Capacity), slots: make(chan struct{}, Capacity)}
	good = true
	go s.run()
	return s, nil
}

func ValidToken(token string) bool {
	if len(token) < 32 || len(token) > 4096 {
		return false
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func validNamespace(s string) bool {
	return len(s) > 0 && len(s) <= 1024 && !strings.ContainsAny(s, "\r\n\x00")
}

func (s *Service) Close() { s.cancel(); <-s.done }

func (s *Service) Stats() Stats {
	return Stats{Reads: s.reads.Load(), Writes: s.writes.Load(), Commits: s.commits.Load(), Conflicts: s.conflicts.Load(), Rejected: s.rejected.Load(), Admitted: len(s.slots)}
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	digest := sha256.Sum256([]byte(token))
	if !ok || subtle.ConstantTimeCompare(s.token[:], digest[:]) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if (r.URL.Path != HeadPath && r.URL.Path != "/v1/stats") || r.URL.RawQuery != "" || r.Header.Get("X-CDS-Namespace") != s.namespace {
		http.Error(w, "unknown namespace or path", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.rejected.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if r.URL.Path == "/v1/stats" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(s.Stats())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	c := command{ctx: ctx, write: r.Method == http.MethodPut, reply: make(chan result, 1)}
	if c.write {
		c.expected = r.Header.Get("If-Match")
		create := r.Header.Get("If-None-Match")
		if (c.expected == "" && create != "*") || (c.expected != "" && create != "") || len(c.expected) > 128 {
			http.Error(w, "exactly one conditional header required", http.StatusBadRequest)
			return
		}
		var err error
		c.value, err = io.ReadAll(http.MaxBytesReader(w, r.Body, MaxHeadBytes))
		if err != nil || len(c.value) == 0 {
			http.Error(w, "invalid head", http.StatusBadRequest)
			return
		}
	}
	select {
	case <-s.done:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	case <-ctx.Done():
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	case s.inbox <- c:
	}
	select {
	case <-s.done:
		w.WriteHeader(http.StatusServiceUnavailable)
	case <-ctx.Done():
		w.WriteHeader(http.StatusServiceUnavailable)
	case answer := <-c.reply:
		if answer.etag != "" {
			w.Header().Set("ETag", answer.etag)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(answer.status)
		_, _ = w.Write(answer.value)
	}
}

func (s *Service) run() {
	defer close(s.done)
	defer s.db.Close()
	for {
		if s.ctx.Err() != nil {
			return
		}
		select {
		case <-s.ctx.Done():
			return
		case c := <-s.inbox:
			if c.ctx.Err() != nil {
				c.reply <- result{status: http.StatusServiceUnavailable}
				continue
			}
			c.reply <- s.execute(c)
		}
	}
}

func (s *Service) execute(c command) result {
	failed := result{status: http.StatusServiceUnavailable}
	if !c.write {
		s.reads.Add(1)
		var answer result
		err := s.db.QueryRowContext(c.ctx, `SELECT etag,value FROM head WHERE id=1`).Scan(&answer.etag, &answer.value)
		if errors.Is(err, sql.ErrNoRows) {
			return result{status: http.StatusNotFound}
		}
		if err != nil {
			return failed
		}
		answer.status = http.StatusOK
		return answer
	}
	s.writes.Add(1)
	tx, err := s.db.BeginTx(c.ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return failed
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRowContext(c.ctx, `SELECT etag FROM head WHERE id=1`).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return failed
	}
	if previous != c.expected {
		s.conflicts.Add(1)
		return result{status: http.StatusPreconditionFailed}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return failed
	}
	etag := `"` + hex.EncodeToString(nonce[:]) + `"`
	digest := sha256.Sum256(c.value)
	// The encrypted publication and its durable receipt are one transaction.
	// A crash cannot acknowledge one without retaining the other. The receipt
	// is diagnostic only; the committed head/history decides recovery.
	if _, err := tx.ExecContext(c.ctx, `INSERT INTO receipts(etag,previous,digest) VALUES(?,?,?)`, etag, previous, digest[:]); err != nil {
		return failed
	}
	if _, err := tx.ExecContext(c.ctx, `INSERT INTO head(id,etag,value) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET etag=excluded.etag,value=excluded.value`, etag, c.value); err != nil {
		return failed
	}
	if err := tx.Commit(); err != nil {
		return failed
	}
	s.commits.Add(1)
	return result{status: http.StatusNoContent, etag: etag}
}
