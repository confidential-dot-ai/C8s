// Package admissionhistory records a sandbox's cumulative container inventory.
package admissionhistory

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// ErrOverBudget reports a history past the size CDS accepts. It is permanent
// for the sandbox: later records are dropped and every snapshot fails.
var ErrOverBudget = fmt.Errorf("admission history exceeds %d encoded bytes", workloadclaims.MaxResponseBytes)

// History retains distinct admissions for a sandbox's lifetime. The zero value
// is ready to use; callers must synchronise access.
type History struct {
	byKey      map[string]workloadclaims.SandboxContainer
	unresolved map[string]struct{}
	// bytes approximates the encoded history so a launch configuration that
	// changes on every restart cannot grow it without bound.
	bytes      int
	overBudget bool
}

// Record adds an admission; only a resolved record for the same ID clears an
// unresolved container. History owns its copy of argv.
// Nil mounts means unavailable evidence; a non-nil empty slice means no mounts.
// Record returns ErrOverBudget once, on the record that crosses the budget.
func (h *History) Record(id, digest string, argv []string, env *allowlist.EnvObservation, mounts ...allowlist.ObservedMount) error {
	if h.overBudget {
		return nil
	}
	if h.byKey == nil {
		h.byKey = map[string]workloadclaims.SandboxContainer{}
		h.unresolved = map[string]struct{}{}
	}
	if digest == "" {
		if _, ok := h.unresolved[id]; !ok {
			h.unresolved[id] = struct{}{}
			return h.grow(len(id))
		}
		return nil
	}
	delete(h.unresolved, id)
	c := workloadclaims.SandboxContainer{Digest: digest, Argv: slices.Clone(argv), Env: env.Clone(), Mounts: slices.Clone(mounts)}
	slices.SortFunc(c.Mounts, compareObservedMounts)
	key := c.Key()
	if _, ok := h.byKey[key]; ok {
		h.byKey[key] = c
		return nil
	}
	// Marshal cannot fail: SandboxContainer holds only strings, bools and maps
	// of strings.
	encoded, _ := json.Marshal(c)
	if err := h.grow(len(encoded) + len(digest)); err != nil {
		return err
	}
	h.byKey[key] = c
	return nil
}

func (h *History) grow(n int) error {
	h.bytes += n
	if h.bytes <= workloadclaims.MaxResponseBytes {
		return nil
	}
	h.overBudget = true
	h.byKey, h.unresolved = nil, nil
	return ErrOverBudget
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
	if h.overBudget {
		return nil, nil, ErrOverBudget
	}
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
