package cds

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// seedRecheckInterval is how often a following CDS rereads the seed. A package
// var so tests can shorten it.
var seedRecheckInterval = 30 * time.Second

// startSeed seeds store from path and, when follow is set, starts following
// it until ctx is done. Only a seed no one can change may be followed:
// whoever can write it publishes entries without an operator token.
// The returned channel closes once the follower has stopped; close store only
// after it does.
func startSeed(ctx context.Context, store *allowlist.Store, path string, follow bool) (<-chan struct{}, error) {
	done := make(chan struct{})
	applied, err := seedStore(store, path)
	if err != nil {
		return nil, err
	}
	if !follow {
		close(done)
		return done, nil
	}
	slog.Info("following the allowlist seed", "path", path, "interval", seedRecheckInterval)
	t := time.NewTicker(seedRecheckInterval)
	go func() {
		defer close(done)
		defer t.Stop()
		followSeed(ctx, store, path, applied, t.C)
	}()
	return done, nil
}

// seedStore reads the JSON allowlist at path, seeds its workload entries into
// store and returns the content it applied. It owns the file/wire-format
// concerns; the version-stable merge is Store.SeedWorkloads.
//
// Seeding runs before the HTTP server serves, so the first GET /allowlist
// reflects the seed. Any error fails closed: CDS must not serve an empty or
// partial allowlist because its seed could not be applied.
func seedStore(store *allowlist.Store, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist seed %q: %w", path, err)
	}

	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist seed %q: %w", path, err)
	}

	added, retired, err := store.SeedWorkloads(seed.Workloads)
	if err != nil {
		return nil, fmt.Errorf("seed allowlist workloads: %w", err)
	}

	slog.Info("allowlist seeded", "workloads_added", added, "workloads_retired", retired, "workloads_in_seed", len(seed.Workloads))
	return data, nil
}

// followSeed seeds store again on each tick at which the content at path
// differs from applied, until ctx is done, so a changed seed is published
// without a restart that would reset a memory-backed store.
// Unchanged content is not reseeded, so an entry deleted since stays deleted
// until the seed changes.
func followSeed(ctx context.Context, store *allowlist.Store, path string, applied []byte, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.Equal(data, applied) {
			// A read error is retried on the next tick: the kubelet swaps a
			// ConfigMap volume's content under the path.
			continue
		}
		if data, err = seedStore(store, path); err != nil {
			slog.Error("allowlist seed changed but was not applied; retrying", "error", err)
			continue
		}
		applied = data
	}
}
