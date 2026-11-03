package snapshotcache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestWaiterAfterRevocationCannotUseEarlierRefresh(t *testing.T) {
	var cache Cache[uint64, string]
	var gen, loads atomic.Uint64
	gen.Store(1)
	started, release := make(chan struct{}), make(chan struct{})
	stamp := func() (uint64, error) { return gen.Load(), nil }
	build := func() (string, error) {
		if loads.Add(1) == 1 {
			close(started)
			<-release
			return "old grant", nil
		}
		return "revoked", nil
	}
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = cache.Load(t.Context(), stamp, build) })
	<-started
	gen.Store(2) // The revocation was acknowledged before these callers begin.
	for range 32 {
		wg.Go(func() {
			value, err := cache.Load(t.Context(), stamp, build)
			if err != nil || value != "revoked" {
				t.Errorf("post-revocation read = %q, %v", value, err)
			}
		})
	}
	close(release)
	wg.Wait()
	if loads.Load() != 2 {
		t.Fatalf("burst performed %d loads, want two generations", loads.Load())
	}
}

func TestCanceledWaiterAndFailedRefreshNeverUseOldView(t *testing.T) {
	var cache Cache[int, string]
	gen := func() (int, error) { return 1, nil }
	_, _ = cache.Load(t.Context(), gen, func() (string, error) { return "grant", nil })
	started, release := make(chan struct{}), make(chan struct{})
	gen = func() (int, error) { return 2, nil }
	failure := errors.New("store unavailable")
	owner := make(chan error, 1)
	go func() {
		_, err := cache.Load(t.Context(), gen, func() (string, error) { close(started); <-release; return "", failure })
		owner <- err
	}()
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := cache.Load(ctx, gen, func() (string, error) { t.Fatal("canceled caller loaded"); return "", nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if err := <-owner; !errors.Is(err, failure) {
		t.Fatal(err)
	}
	value, err := cache.Load(t.Context(), gen, func() (string, error) { return "", failure })
	if value != "" || !errors.Is(err, failure) {
		t.Fatalf("failed refresh fell back to %q, %v", value, err)
	}
}

func BenchmarkWarmRead(b *testing.B) {
	var cache Cache[uint64, int]
	gen := func() (uint64, error) { return 1, nil }
	build := func() (int, error) { return 42, nil }
	_, _ = cache.Load(b.Context(), gen, build)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = cache.Load(b.Context(), gen, build)
		}
	})
}
