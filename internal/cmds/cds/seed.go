package cds

import (
	"fmt"
	"log/slog"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// seedWorkloads seeds the measured configuration's workload entries into
// store; the version-stable merge is Store.SeedWorkloads.
//
// Seeding runs before the HTTP server serves, so the first GET /allowlist
// reflects the configuration. Any error fails closed: CDS must not serve an
// empty or partial allowlist because its seed could not be applied.
func seedWorkloads(store *allowlist.Store, seed *pkgallowlist.Allowlist) error {
	added, retired, err := store.SeedWorkloads(seed.Workloads)
	if err != nil {
		return fmt.Errorf("seed allowlist workloads: %w", err)
	}

	slog.Info("allowlist seeded", "workloads_added", added, "workloads_retired", retired, "workloads_in_seed", len(seed.Workloads))
	return nil
}
