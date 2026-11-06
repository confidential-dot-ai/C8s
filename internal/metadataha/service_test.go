package metadataha

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

type controlledBackend struct {
	entered      chan string
	block        chan struct{}
	commitErr    error
	active, peak atomic.Int32
}

func (b *controlledBackend) Read(ctx context.Context, ns string, keys []string) ([]metadatapilot.Record, error) {
	if ns == "busy" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := b.active.Add(1)
		defer b.active.Add(-1)
		for old := b.peak.Load(); n > old; old = b.peak.Load() {
			if b.peak.CompareAndSwap(old, n) {
				break
			}
		}
		b.entered <- ns
		select {
		case <-b.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	r := make([]metadatapilot.Record, len(keys))
	for i, k := range keys {
		r[i].Key = k
	}
	return r, nil
}
func (b *controlledBackend) Commit(context.Context, string, metadatapilot.Transaction) error {
	return b.commitErr
}

func stateRequest(ns, token, path string, body any) *http.Request {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "https://metadata"+path, bytes.NewReader(b))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-CDS-Namespace", ns)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestClusterBackpressureAndCancellation(t *testing.T) {
	b := &controlledBackend{entered: make(chan string, Capacity), block: make(chan struct{})}
	tokenA, tokenB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	s, err := New([]metadatapilot.ClusterConfig{{Namespace: "busy", Token: tokenA}, {Namespace: "other", Token: tokenB}}, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	txn := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: strings.Repeat("a", 64)}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for range Capacity {
		wg.Go(func() {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, stateRequest("busy", tokenA, metadatapilot.StateReadPath, txn).WithContext(ctx))
		})
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.clusters["busy"].gate.Stats().Admitted != Capacity && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.clusters["busy"].gate.Stats().Admitted != Capacity {
		t.Fatal("did not fill bounded cluster admission")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, stateRequest("busy", tokenA, metadatapilot.StateReadPath, txn))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("overload HTTP %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, stateRequest("other", tokenB, metadatapilot.StateReadPath, txn))
	if w.Code != http.StatusOK {
		t.Fatalf("other cluster starved: HTTP %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, stateRequest("other", tokenA, metadatapilot.StateReadPath, txn))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("foreign cluster token accepted")
	}
	cancel()
	wg.Wait()
	if got := b.peak.Load(); got > Workers {
		t.Fatalf("%d backend operations exceeded active bound %d", got, Workers)
	}
}

func TestCommitErrorClassification(t *testing.T) {
	key := strings.Repeat("a", 64)
	token := strings.Repeat("a", 32)
	txn := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: key}}, Writes: []metadatapilot.Record{{Key: key, Version: "0000000000000001", Value: []byte("ciphertext")}}}
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{{"committed", nil, 204}, {"conflict", objectwal.ErrConflict, 412}, {"lost reply", objectwal.ErrInDoubt, 503}, {"quorum", errors.New("unavailable"), 503}, {"backend busy after send", objectwal.ErrBackpressure, 503}} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New([]metadatapilot.ClusterConfig{{Namespace: "a", Token: token}}, &controlledBackend{commitErr: tc.err})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			w := httptest.NewRecorder()
			s.ServeHTTP(w, stateRequest("a", token, metadatapilot.StateCommitPath, txn))
			if w.Code != tc.want {
				t.Fatalf("HTTP %d want %d", w.Code, tc.want)
			}
		})
	}
}

func TestAdmissionConfigurationAndRequestValidation(t *testing.T) {
	token := strings.Repeat("x", 32)
	cfg := metadatapilot.ClusterConfig{Namespace: "one", Token: token}
	b := &controlledBackend{}
	if _, err := New([]metadatapilot.ClusterConfig{cfg, {Namespace: "two", Token: token}}, b); err == nil {
		t.Fatal("duplicate credential grants cross-cluster access")
	}
	s, err := New([]metadatapilot.ClusterConfig{cfg}, b)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	txn := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: strings.Repeat("a", 64)}}}
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"plaintext", func(r *http.Request) { r.TLS = nil }, 400},
		{"wrong method", func(r *http.Request) { r.Method = http.MethodGet }, 405},
		{"query", func(r *http.Request) { r.URL.RawQuery = "revision=1" }, 404},
		{"wrong namespace", func(r *http.Request) { r.Header.Set("X-CDS-Namespace", "two") }, 401},
		{"legacy head", func(r *http.Request) { r.URL.Path = metadatapilot.HeadPath }, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := stateRequest("one", token, metadatapilot.StateReadPath, txn)
			tc.mutate(r)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("HTTP %d", w.Code)
			}
		})
	}
}
