// Package admissionhistory records a sandbox's cumulative container inventory.
package admissionhistory

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// MaxVariableEvidenceRecords bounds how many records keep per-variable env
// digests. Each can reach about 13 KB against CDS's 1 MiB inventory limit;
// older records keep their aggregate digest only.
const MaxVariableEvidenceRecords = 16

// History retains distinct admissions for a sandbox's lifetime. The zero value
// is ready to use; callers must synchronise access.
type History struct {
	byKey      map[string]record
	unresolved map[string]struct{}
	seq        uint64
}

type record struct {
	container workloadclaims.SandboxContainer
	seq       uint64
}

// Record adds an admission; only a resolved record for the same ID clears an
// unresolved container. History owns its copy of argv.
// Nil mounts means unavailable evidence; a non-nil empty slice means no mounts.
func (h *History) Record(id, digest string, argv []string, env *allowlist.EnvObservation, mounts ...allowlist.ObservedMount) {
	if h.byKey == nil {
		h.byKey = map[string]record{}
		h.unresolved = map[string]struct{}{}
	}
	if digest == "" {
		h.unresolved[id] = struct{}{}
		return
	}
	delete(h.unresolved, id)
	c := workloadclaims.SandboxContainer{Digest: digest, Argv: slices.Clone(argv), Env: env.Clone(), Mounts: slices.Clone(mounts)}
	slices.SortFunc(c.Mounts, compareObservedMounts)
	h.seq++
	h.byKey[c.Key()] = record{container: c, seq: h.seq}
	h.boundVariableEvidence()
}

// boundVariableEvidence drops per-variable digests from the oldest records
// beyond MaxVariableEvidenceRecords. The record and its aggregate digest stay.
func (h *History) boundVariableEvidence() {
	var withEvidence []string
	for key, r := range h.byKey {
		if r.container.Env != nil && r.container.Env.VariableDigests != nil {
			withEvidence = append(withEvidence, key)
		}
	}
	if len(withEvidence) <= MaxVariableEvidenceRecords {
		return
	}
	slices.SortFunc(withEvidence, func(a, b string) int { return cmp.Compare(h.byKey[a].seq, h.byKey[b].seq) })
	for _, key := range withEvidence[:len(withEvidence)-MaxVariableEvidenceRecords] {
		r := h.byKey[key]
		delete(h.byKey, key)
		r.container.Env.VariableDigests = nil
		if _, merged := h.byKey[r.container.Key()]; !merged {
			h.byKey[r.container.Key()] = r
		}
	}
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
	for _, r := range h.byKey {
		c := r.container
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
