package requestgate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newGate(t *testing.T, workers, capacity int) *Gate {
	t.Helper()
	g, err := New(t.Context(), workers, capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	return g
}

func waitFor(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for admission")
		case <-tick.C:
		}
	}
}

type unreadBody struct{ reads atomic.Int64 }

func (b *unreadBody) Read([]byte) (int, error) { b.reads.Add(1); return 0, io.EOF }
func (*unreadBody) Close() error               { return nil }

func TestBoundIncludesActiveAndCanceledWorkAndRefusesBeforeBody(t *testing.T) {
	g := newGate(t, 1, 2)
	release, err := g.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(t.Context())
	queued := make(chan error, 1)
	go func() {
		permit, err := g.Acquire(ctx)
		if permit != nil {
			permit()
		}
		queued <- err
	}()
	waitFor(t, func() bool { return g.Stats().Admitted == 2 })
	body := &unreadBody{}
	r := httptest.NewRequest(http.MethodPost, "/attest", body)
	w := httptest.NewRecorder()
	g.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("overflow reached handler") })).ServeHTTP(w, r)
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" || body.reads.Load() != 0 {
		t.Fatalf("overflow code=%d retry=%q body reads=%d", w.Code, w.Header().Get("Retry-After"), body.reads.Load())
	}
	cancel()
	if err := <-queued; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return g.Stats().Admitted == 1 })
	release()
	release() // A duplicate release cannot mint another permit.
	waitFor(t, func() bool { return g.Stats().Admitted == 0 })
}

func TestClusterIsolationAndShutdownCancelsActiveAndQueued(t *testing.T) {
	a, b := newGate(t, 1, 2), newGate(t, 1, 2)
	entered, finished := make(chan struct{}), make(chan struct{})
	h := a.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/attest", nil))
		close(finished)
	}()
	<-entered
	queued := make(chan error, 1)
	go func() {
		permit, err := a.Acquire(t.Context())
		if permit != nil {
			permit()
		}
		queued <- err
	}()
	waitFor(t, func() bool { return a.Stats().Admitted == 2 })
	permit, err := b.Acquire(t.Context())
	if err != nil {
		t.Fatalf("cluster A exhausted cluster B: %v", err)
	}
	permit()
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not drain")
	}
	<-finished
	if err := <-queued; !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if stats := a.Stats(); stats.Active != 0 || stats.Admitted != 0 {
		t.Fatal(stats)
	}
	if _, err := a.Acquire(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestConcurrentBurstsCancelAndClose(t *testing.T) {
	for range 20 {
		g := newGate(t, 4, 16)
		var wg sync.WaitGroup
		var active, peak atomic.Int64
		start := make(chan struct{})
		for i := range 64 {
			wg.Go(func() {
				<-start
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if i%3 == 0 {
					cancel()
				}
				permit, err := g.Acquire(ctx)
				if err != nil {
					return
				}
				n := active.Add(1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				active.Add(-1)
				permit()
				permit()
			})
		}
		close(start)
		wg.Go(g.Close)
		wg.Wait()
		if peak.Load() > 4 || g.Stats().Admitted != 0 {
			t.Fatalf("peak=%d stats=%+v", peak.Load(), g.Stats())
		}
	}
}
