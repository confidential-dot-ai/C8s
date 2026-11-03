package cds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
)

func TestQueuedReleaseChecksFreshnessAfterAdmissionAndControlProgresses(t *testing.T) {
	work, _ := requestgate.New(t.Context(), 1, 2)
	control, _ := requestgate.New(t.Context(), 1, 2)
	a := &requestAdmission{workload: work, control: control}
	t.Cleanup(a.Close)
	var committed, applied atomic.Uint64
	committed.Store(1)
	applied.Store(1)
	var confirmations atomic.Int64
	backend := haGate(func() bool { return true }, func() error {
		confirmations.Add(1)
		applied.Store(committed.Load())
		return nil
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			committed.Store(2) // An acknowledged policy revocation.
			w.WriteHeader(http.StatusNoContent)
		} else if applied.Load() == 1 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	h := a.Handler(backend)
	permit, err := work.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer permit()
	read := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/secrets/api/key", nil))
		read <- w.Code
	}()
	deadline := time.Now().Add(5 * time.Second)
	for work.Stats().Admitted != 2 {
		if time.Now().After(deadline) {
			t.Fatal("secret read did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	if confirmations.Load() != 0 {
		t.Fatal("freshness was checked before admission")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("PUT", "/allowlist", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("join burst blocked revocation: HTTP %d", w.Code)
	}
	permit()
	select {
	case code := <-read:
		if code != http.StatusForbidden {
			t.Fatalf("queued read used pre-revocation policy: HTTP %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued release did not finish")
	}
}

func TestHealthAndPeerForwardingDoNotDependOnClientPermits(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	work, _ := requestgate.New(ctx, 1, 1)
	control, _ := requestgate.New(ctx, 1, 1)
	a := &requestAdmission{workload: work, control: control}
	t.Cleanup(a.Close)
	wRelease, _ := work.Acquire(ctx)
	cRelease, _ := control.Acquire(ctx)
	defer wRelease()
	defer cRelease()
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"GET", "/healthz", 204}, {"GET", "/readyz", 204},
		{"POST", cdsobject.ForwardPath, 204},
		{"POST", "/attest", 503}, {"PUT", "/allowlist", 503},
		{"GET", cdsobject.ForwardPath, 503}, // No generic path-based bypass.
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.code {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.path, w.Code, tc.code)
		}
	}
}
