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

// seedRecheckInterval is how often followSeed rereads the seed. A package var
// so tests can shorten it.
var seedRecheckInterval = 30 * time.Second

// seedStore reads the JSON allowlist at path, seeds its workload entries into
// store and returns the content it applied. It owns the file/wire-format
// concerns; the additive, version-stable merge is Store.SeedWorkloads.
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

	added, err := store.SeedWorkloads(seed.Workloads)
	if err != nil {
		return nil, fmt.Errorf("seed allowlist workloads: %w", err)
	}

	slog.Info("allowlist seeded", "workloads_added", added, "workloads_in_seed", len(seed.Workloads))
	return data, nil
}

// followSeed seeds store again each time the content at path differs from
// applied, until ctx is done. A chart upgrade rewrites the mounted seed in
// place, so the running CDS publishes the new release's entries and the
// enforcers admit its components on their next pull, without a CDS restart
// that would reset a memory-backed store. Unchanged content is not reseeded,
// so an entry deleted since stays deleted until the seed changes.
func followSeed(ctx context.Context, store *allowlist.Store, path string, applied []byte) {
	t := time.NewTicker(seedRecheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
