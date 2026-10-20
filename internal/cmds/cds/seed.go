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

// startSeed applies the seed at path and, when follow is set, starts following
// it until ctx is done. Only a seed no one can change may be followed:
// whoever can write it publishes entries without an operator token.
//
// A followed seed is the measured node image's. It becomes the seed layer of
// layers and is never written to the store, so an operator upload carries only
// application entries and cannot drop it. A seed read once (a chart-managed
// install's ConfigMap) is merged into the store, which an upload replaces.
//
// The returned channel closes once the follower has stopped; close the store
// only after it does.
func startSeed(ctx context.Context, layers *allowlist.Layered, path string, follow bool) (<-chan struct{}, error) {
	done := make(chan struct{})
	if !follow {
		if _, err := seedStore(layers.Store, path); err != nil {
			return nil, err
		}
		close(done)
		return done, nil
	}
	applied, err := seedLayer(layers, path)
	if err != nil {
		return nil, err
	}
	slog.Info("following the measured allowlist seed as its own layer", "path", path, "interval", seedRecheckInterval)
	t := time.NewTicker(seedRecheckInterval)
	go func() {
		defer close(done)
		defer t.Stop()
		followSeed(ctx, layers, path, applied, t.C)
	}()
	return done, nil
}

// readSeed reads and parses the JSON allowlist at path. Any error fails
// closed: CDS must not decide on an empty or partial allowlist because its
// seed could not be applied.
func readSeed(path string) ([]byte, *pkgallowlist.Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read allowlist seed %q: %w", path, err)
	}
	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse allowlist seed %q: %w", path, err)
	}
	return data, seed, nil
}

// seedStore reads the JSON allowlist at path, seeds its workload entries into
// store and returns the content it applied. It owns the file/wire-format
// concerns; the version-stable merge is Store.SeedWorkloads.
//
// Seeding runs before the HTTP server serves, so the first GET /allowlist
// reflects the seed.
func seedStore(store *allowlist.Store, path string) ([]byte, error) {
	data, seed, err := readSeed(path)
	if err != nil {
		return nil, err
	}
	added, retired, err := store.SeedWorkloads(seed.Workloads)
	if err != nil {
		return nil, fmt.Errorf("seed allowlist workloads: %w", err)
	}
	slog.Info("allowlist seeded", "workloads_added", added, "workloads_retired", retired, "workloads_in_seed", len(seed.Workloads))
	return data, nil
}

// seedLayer reads the JSON allowlist at path, sets it as the seed layer of
// layers and returns the content it applied.
func seedLayer(layers *allowlist.Layered, path string) ([]byte, error) {
	data, seed, err := readSeed(path)
	if err != nil {
		return nil, err
	}
	if err := layers.SetSeed(seed); err != nil {
		return nil, err
	}
	slog.Info("allowlist seed layer set", "workloads_in_seed", len(seed.Workloads))
	return data, nil
}

// followSeed sets the seed layer again on each tick at which the content at
// path differs from applied, until ctx is done, so a changed seed takes effect
// without a restart.
func followSeed(ctx context.Context, layers *allowlist.Layered, path string, applied []byte, tick <-chan time.Time) {
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
		if data, err = seedLayer(layers, path); err != nil {
			slog.Error("allowlist seed changed but was not applied; retrying", "error", err)
			continue
		}
		applied = data
	}
}
