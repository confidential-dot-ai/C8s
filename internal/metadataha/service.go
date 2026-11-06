// Package metadataha serves encrypted current records through a replicated
// transactional authority. It never receives CDS state or CA decryption keys.
package metadataha

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
)

// Backend must provide strictly serializable reads and atomic checked commits.
// A commit error other than ErrConflict or pre-admission ErrBackpressure is
// ambiguous. Callers must not blindly resubmit it.
type Backend interface {
	Read(context.Context, string, []string) ([]metadatapilot.Record, error)
	Commit(context.Context, string, metadatapilot.Transaction) error
}

const (
	Workers  = 16
	Capacity = 64
)

type cluster struct {
	token                             [32]byte
	gate                              *requestgate.Gate
	reads, writes, commits, conflicts atomic.Uint64
}

// Service has an immutable cluster table. Each cluster owns its admission
// actor; network IO runs in bounded request owners, never in that actor.
type Service struct {
	clusters map[string]*cluster
	backend  Backend
	ctx      context.Context
	cancel   context.CancelFunc
}

func New(configs []metadatapilot.ClusterConfig, backend Backend) (*Service, error) {
	if backend == nil || len(configs) == 0 || len(configs) > metadatapilot.MaxClusters {
		return nil, errors.New("metadata HA requires a backend and 1..256 configured clusters")
	}
	names, tokens := map[string]bool{}, map[[32]byte]bool{}
	for _, c := range configs {
		h := sha256.Sum256([]byte(c.Token))
		if c.Namespace == "" || len(c.Namespace) > 1024 || strings.ContainsAny(c.Namespace, "\r\n\x00") ||
			!metadatapilot.ValidToken(c.Token) || names[c.Namespace] || tokens[h] {
			return nil, errors.New("metadata HA: invalid or duplicate namespace/token")
		}
		names[c.Namespace], tokens[h] = true, true
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{clusters: make(map[string]*cluster), backend: backend, ctx: ctx, cancel: cancel}
	for _, cfg := range configs {
		gate, err := requestgate.New(ctx, Workers, Capacity)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.clusters[cfg.Namespace] = &cluster{token: sha256.Sum256([]byte(cfg.Token)), gate: gate}
	}
	return s, nil
}

func (s *Service) Close() {
	s.cancel()
	for _, c := range s.clusters {
		c.gate.Close()
	}
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}
	namespace := r.Header.Get("X-CDS-Namespace")
	c := s.clusters[namespace]
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	digest := sha256.Sum256([]byte(token))
	if c == nil || !ok || subtle.ConstantTimeCompare(c.token[:], digest[:]) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	read := r.URL.Path == metadatapilot.StateReadPath
	stats := r.URL.Path == "/v1/stats"
	if r.URL.RawQuery != "" || (!read && !stats && r.URL.Path != metadatapilot.StateCommitPath) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if (stats && r.Method != http.MethodGet) || (!stats && r.Method != http.MethodPost) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	release, err := c.gate.Acquire(ctx)
	if err != nil {
		code := http.StatusServiceUnavailable
		if errors.Is(err, requestgate.ErrBusy) {
			code = http.StatusTooManyRequests
		}
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(code)
		return
	}
	defer release()
	w.Header().Set("Cache-Control", "no-store")
	if stats {
		g := c.gate.Stats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadatapilot.Stats{Reads: c.reads.Load(), Writes: c.writes.Load(),
			Commits: c.commits.Load(), Conflicts: c.conflicts.Load(), Rejected: g.Rejected, Admitted: g.Admitted})
		return
	}
	var txn metadatapilot.Transaction
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, metadatapilot.MaxTransactionBytes))
	d.DisallowUnknownFields()
	if err := d.Decode(&txn); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := d.Token(); err != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := txn.Check(read); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if read {
		keys := make([]string, len(txn.Checks))
		for i, check := range txn.Checks {
			keys[i] = check.Key
		}
		rows, err := s.backend.Read(ctx, namespace, keys)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		c.reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
		return
	}
	c.writes.Add(1)
	if err := s.backend.Commit(ctx, namespace, txn); err != nil {
		if errors.Is(err, objectwal.ErrConflict) {
			c.conflicts.Add(1)
			w.WriteHeader(http.StatusPreconditionFailed)
		} else {
			// Never mislabel a sent write as a definite refusal.
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
	c.commits.Add(1)
	w.WriteHeader(http.StatusNoContent)
}
