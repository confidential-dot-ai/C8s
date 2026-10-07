// Package admissionhistory records a sandbox's cumulative container inventory.
package admissionhistory

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// History retains distinct admissions for a sandbox's lifetime. The zero value
// is ready to use; callers must synchronise access.
type History struct {
	byKey      map[string]workloadclaims.SandboxContainer
	unresolved map[string]struct{}
}

// Record adds an admission; only a resolved record for the same ID clears an
// unresolved container. History owns its copy of argv. role is the platform
// role the node's measured base binds to the launch, empty for a container
// outside every role.
// Nil mounts means unavailable evidence; a non-nil empty slice means no mounts.
func (h *History) Record(id, digest, role string, argv []string, env *allowlist.EnvObservation, mounts ...allowlist.ObservedMount) {
	if h.byKey == nil {
		h.byKey = map[string]workloadclaims.SandboxContainer{}
		h.unresolved = map[string]struct{}{}
	}
	if digest == "" {
		h.unresolved[id] = struct{}{}
		return
	}
	delete(h.unresolved, id)
	c := workloadclaims.SandboxContainer{
		Digest: digest,
		Role:   role,
		Argv:   slices.Clone(argv),
		Env:    env.Clone(),
		Mounts: slices.Clone(mounts),
	}
	slices.SortFunc(c.Mounts, compareObservedMounts)
	h.byKey[c.Key()] = c
}

func compareObservedMounts(a, b allowlist.ObservedMount) int {
	order := cmp.Or(
		cmp.Compare(a.Destination, b.Destination),
		cmp.Compare(a.Class, b.Class),
		cmp.Compare(a.Storage, b.Storage),
		cmp.Compare(a.HostSourceDigest, b.HostSourceDigest),
	)
	if order != 0 || a.ReadOnly == b.ReadOnly {
		return order
	}
	if a.ReadOnly {
		return 1
	}
	return -1
}

// Snapshot returns sorted, independent copies of the digest set and admissions.
// An unresolved container makes the entire snapshot unavailable.
func (h History) Snapshot() ([]string, []workloadclaims.SandboxContainer, error) {
	if len(h.unresolved) > 0 {
		return nil, nil, fmt.Errorf("admitted a container with no resolved image digest")
	}
	digests := []string{}
	containers := make([]workloadclaims.SandboxContainer, 0, len(h.byKey))
	for _, c := range h.byKey {
		digests = append(digests, c.Digest)
		c.Argv = slices.Clone(c.Argv)
		c.Env = c.Env.Clone()
		c.Mounts = slices.Clone(c.Mounts)
		containers = append(containers, c)
	}
	slices.Sort(digests)
	slices.SortFunc(containers, workloadclaims.SandboxContainer.Compare)
	return slices.Compact(digests), containers, nil
}
