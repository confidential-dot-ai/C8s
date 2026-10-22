package cds

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// openSeed applies the allowlist seed at path (none when path is empty) and
// returns the allowlist CDS decides on. With layer set the seed is the
// measured node image's: it becomes the fixed seed layer for this boot and
// never enters the store. Otherwise it is merged into store, which an upload
// replaces. Any error fails closed: CDS must not decide on an empty or partial
// allowlist because its seed could not be applied.
func openSeed(store *allowlist.Store, path string, layer bool) (*allowlist.Layered, error) {
	if path == "" {
		return allowlist.NewLayered(store, nil)
	}
	if !layer {
		if err := seedStore(store, path); err != nil {
			return nil, err
		}
		return allowlist.NewLayered(store, nil)
	}
	seed, err := readSeed(path)
	if err != nil {
		return nil, err
	}
	layers, err := allowlist.NewLayered(store, seed)
	if err != nil {
		return nil, err
	}
	slog.Info("allowlist seed kept as a fixed layer", "digest", layers.SeedDigest(), "workloads_in_seed", len(seed.Workloads))
	return layers, nil
}

func readSeed(path string) (*pkgallowlist.Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist seed %q: %w", path, err)
	}
	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist seed %q: %w", path, err)
	}
	return seed, nil
}

// seedStore reads the JSON allowlist at path and seeds its workload entries
// into store. It owns the file/wire-format concerns; the version-stable merge
// is Store.SeedWorkloads. Seeding runs before the HTTP server serves, so the
// first GET /allowlist reflects the seed.
func seedStore(store *allowlist.Store, path string) error {
	seed, err := readSeed(path)
	if err != nil {
		return err
	}
	added, retired, err := store.SeedWorkloads(seed.Workloads)
	if err != nil {
		return fmt.Errorf("seed allowlist workloads: %w", err)
	}
	slog.Info("allowlist seeded", "workloads_added", added, "workloads_retired", retired, "workloads_in_seed", len(seed.Workloads))
	return nil
}
