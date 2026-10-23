package cds

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// openSeed seeds store from storeSeed and returns the allowlist CDS decides
// on, with the seed at layerSeed as its fixed seed layer; an empty path means
// none. Only a seed no one can change may be a layer, such as the measured node
// image's: it is read once and never enters the store, so no write drops it.
// Any error fails closed: CDS must not decide on an empty or partial allowlist
// because a seed could not be applied.
func openSeed(store *allowlist.Store, storeSeed, layerSeed string) (*allowlist.Layered, error) {
	if storeSeed != "" {
		if err := seedStore(store, storeSeed); err != nil {
			return nil, err
		}
	}
	if layerSeed == "" {
		return allowlist.NewLayered(store, nil)
	}
	seed, err := readSeed(layerSeed)
	if err != nil {
		return nil, err
	}
	layers, err := allowlist.NewLayered(store, seed)
	if err != nil {
		return nil, err
	}
	slog.Info("allowlist seed kept as a fixed layer", "path", layerSeed, "digest", layers.SeedDigest(), "workloads_in_seed", len(seed.Workloads))
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
