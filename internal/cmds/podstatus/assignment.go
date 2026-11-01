package podstatus

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	AssignNoncePath = "/v1/assign/nonce"
	AssignPath      = "/v1/assign"
	// Issued nonces never expire or get evicted. Exhaustion refuses new issuance.
	maxAssignmentNonces = 256
)

type assignmentRecord struct {
	Version    int             `json:"version"`
	Request    json.RawMessage `json:"request"`
	ServingKey []byte          `json:"servingKey"`
}

type assignmentStore interface {
	Load() (*assignmentRecord, error)
	Commit(*assignmentRecord) error
}

// assignmentService serializes the one transition from waiting to assigned.
// Only the record commits it: neither an apply failure nor a service restart
// can return this boot to the waiting state.
type assignmentService struct {
	mu        sync.Mutex
	doc       *launchconfig.Document
	store     assignmentStore
	nonces    map[[podassign.NonceSize]byte]struct{}
	uid       string
	runtime   *nodeservices.PodRuntime
	boundKey  func(context.Context) (*ecdsa.PublicKey, error)
	render    func(*launchconfig.Document) (nodeservices.PodRuntime, error)
	available func(context.Context) error
	apply     func(context.Context, nodeservices.PodRuntime) error
	wake      chan struct{}
}

func newAssignmentService(ctx context.Context, doc *launchconfig.Document, store assignmentStore, key func(context.Context) (*ecdsa.PublicKey, error), render func(*launchconfig.Document) (nodeservices.PodRuntime, error), available func(context.Context) error, apply func(context.Context, nodeservices.PodRuntime) error) (*assignmentService, error) {
	s := &assignmentService{doc: doc, store: store, nonces: make(map[[podassign.NonceSize]byte]struct{}), boundKey: key, render: render, available: available, apply: apply, wake: make(chan struct{}, 1)}
	if doc.Pod != nil {
		s.uid = doc.Pod.UID
		return s, nil
	}
	record, err := store.Load()
	if err != nil {
		return nil, err
	}
	if record != nil {
		if record.Version != 1 {
			return nil, errors.New("unsupported assignment record")
		}
		req, err := podassign.Decode(record.Request)
		if err != nil {
			return nil, fmt.Errorf("assignment record: %w", err)
		}
		peer, err := x509.ParsePKIXPublicKey(record.ServingKey)
		if err != nil {
			return nil, fmt.Errorf("assignment serving key: %w", err)
		}
		pub, err := key(ctx)
		if err != nil {
			return nil, err
		}
		if err := podassign.Verify(pub, peer, req); err != nil {
			return nil, fmt.Errorf("assignment record signature: %w", err)
		}
		assigned, err := launchconfig.AssignedPod(doc, req.Manifest, req.Entries, req.MeshPeers)
		if err != nil {
			return nil, fmt.Errorf("assignment record payload: %w", err)
		}
		runtime, err := render(assigned)
		if err != nil {
			return nil, err
		}
		s.uid = assigned.Pod.UID
		s.runtime = &runtime
		s.wake <- struct{}{}
	}
	return s, nil
}

func (s *assignmentService) assignedUID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.uid }

func (s *assignmentService) serveNonce(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.nonces) >= maxAssignmentNonces {
		http.Error(w, "assignment nonce capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	var nonce [podassign.NonceSize]byte
	for {
		if _, err := rand.Read(nonce[:]); err != nil {
			http.Error(w, "assignment nonce unavailable", http.StatusServiceUnavailable)
			return
		}
		if _, exists := s.nonces[nonce]; !exists {
			break
		}
	}
	s.nonces[nonce] = struct{}{}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, struct {
		Nonce []byte `json:"nonce"`
	}{nonce[:]})
}

func (s *assignmentService) serveAssign(w http.ResponseWriter, r *http.Request) {
	// The bounded body is read before taking the admission lock.
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, podassign.MaxBody))
	if err != nil {
		http.Error(w, "invalid assignment", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uid != "" {
		http.Error(w, "Pod already assigned", http.StatusConflict)
		return
	}
	req, err := podassign.Decode(data)
	if err != nil {
		http.Error(w, "invalid assignment", http.StatusBadRequest)
		return
	}
	var nonce [podassign.NonceSize]byte
	copy(nonce[:], req.Nonce)
	if _, issued := s.nonces[nonce]; !issued {
		http.Error(w, "assignment nonce was not issued", http.StatusBadRequest)
		return
	}
	key, err := s.boundKey(r.Context())
	if err != nil {
		http.Error(w, "launch binding unavailable", http.StatusServiceUnavailable)
		return
	}
	peer := armtls.ServingKey(r.Context())
	if err := podassign.Verify(key, peer, req); err != nil {
		http.Error(w, "invalid assignment signature", http.StatusUnauthorized)
		return
	}
	assigned, err := launchconfig.AssignedPod(s.doc, req.Manifest, req.Entries, req.MeshPeers)
	if err != nil {
		http.Error(w, "invalid assignment payload", http.StatusUnprocessableEntity)
		return
	}
	runtime, err := s.render(assigned)
	if err != nil {
		http.Error(w, "invalid assignment payload", http.StatusUnprocessableEntity)
		return
	}
	if err := s.available(r.Context()); err != nil {
		http.Error(w, "guest runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	spki, err := x509.MarshalPKIXPublicKey(peer)
	if err != nil {
		http.Error(w, "serving key unavailable", http.StatusServiceUnavailable)
		return
	}
	record := &assignmentRecord{Version: 1, Request: bytes.Clone(data), ServingKey: spki}
	if err := s.store.Commit(record); err != nil {
		http.Error(w, "assignment storage unavailable", http.StatusServiceUnavailable)
		return
	}
	// Commit precedes every runtime mutation. From here, always acknowledge the
	// accepted UID; a later apply error is recovered from this immutable record.
	s.uid = assigned.Pod.UID
	s.runtime = &runtime
	clear(s.nonces)
	select {
	case s.wake <- struct{}{}:
	default:
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, struct {
		UID string `json:"uid"`
	}{s.uid})
}

// run retries installation without a guest lifetime deadline. A provider may
// independently retire a VM; recovery never discards its accepted assignment.
func (s *assignmentService) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			runtime := s.runtime
			s.mu.Unlock()
			if runtime == nil {
				break
			}
			applyCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			err := s.apply(applyCtx, *runtime)
			cancel()
			if err == nil {
				break
			}
			slog.Error("recover accepted Pod assignment", "error", err)
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func assignmentPublicKey(pub []byte) (*ecdsa.PublicKey, error) {
	keys, err := operatorauth.ParsePublicKeysPEM(pub)
	if err != nil || len(keys) != 1 || keys[0].Curve != elliptic.P256() {
		return nil, errors.New("assignment requires one ECDSA P-256 launch key")
	}
	return keys[0], nil
}
