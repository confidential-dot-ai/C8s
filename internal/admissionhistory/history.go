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
//
// Records keep their per-variable env digests while the sandbox's total stays
// within allowlist.MaxSandboxVariableEvidenceBytes (see Bound). Whether a
// record needs them is decided when serving (Snapshot), so the policy a node
// holds when it records cannot strip evidence for good.
type History struct {
	byKey      map[string]*record
	unresolved map[string]struct{}
	running    map[string]string // container ID -> record key
	seq        uint64
}

type record struct {
	container     workloadclaims.SandboxContainer
	seq           uint64
	running       map[string]struct{}
	evidenceBytes int
}

// Record adds an admission; only a resolved record for the same ID clears an
// unresolved container. History owns its copy of argv. A container counts as
// running from Record until Exited.
// Nil mounts means unavailable evidence; a non-nil empty slice means no mounts.
func (h *History) Record(id, digest string, argv []string, env *allowlist.EnvObservation, mounts ...allowlist.ObservedMount) {
	if h.byKey == nil {
		h.byKey = map[string]*record{}
		h.unresolved = map[string]struct{}{}
		h.running = map[string]string{}
	}
	h.Exited(id)
	if digest == "" {
		h.unresolved[id] = struct{}{}
		return
	}
	delete(h.unresolved, id)
	c := workloadclaims.SandboxContainer{Digest: digest, Argv: slices.Clone(argv), Env: env.Clone(), Mounts: slices.Clone(mounts)}
	slices.SortFunc(c.Mounts, compareObservedMounts)
	evidence := c.Env.Clone()
	if c.Env != nil {
		c.Env.VariableDigests = nil
		c.Env.VariableDigestsEvicted = false
	}
	// Keyed without per-variable digests: the aggregate digest fixes them, so
	// a later admission of the same environment restores evicted evidence.
	key := c.Key()
	r, ok := h.byKey[key]
	if !ok {
		r = &record{running: map[string]struct{}{}}
		h.byKey[key] = r
	}
	switch {
	case evidence != nil && evidence.VariableDigests != nil:
		c.Env.VariableDigests = evidence.VariableDigests
		r.evidenceBytes = evidence.VariableEvidenceBytes()
	case ok && c.Env != nil:
		c.Env.VariableDigests = r.container.Env.VariableDigests
		c.Env.VariableDigestsEvicted = r.container.Env.VariableDigestsEvicted
	}
	r.container = c
	h.seq++
	r.seq = h.seq
	r.running[id] = struct{}{}
	h.running[id] = key
}

// Exited marks a container as no longer running, which makes its record's
// per-variable evidence the first of its image's that Bound evicts.
func (h *History) Exited(id string) {
	key, ok := h.running[id]
	if !ok {
		return
	}
	delete(h.running, id)
	delete(h.byKey[key].running, id)
}

// Bound evicts per-variable digests until the sandbox's total fits within
// allowlist.MaxSandboxVariableEvidenceBytes. It ranks records by whether
// needed reports their image needing them, then by whether a container still
// runs, and evicts the lowest-ranked, oldest first. Need outranks liveness
// because an exited init container's record still has to match; liveness
// still ranks within each, so a running container keeps its evidence while a
// node that has not applied its policy yet reports no image as needed. Each
// record keeps its aggregate digest and is marked evicted. A nil needed treats
// every image as needing them.
func (h *History) Bound(needed func(digest string) bool) {
	total := 0
	var holding []*record
	for _, r := range h.byKey {
		if r.evidenceBytes > 0 {
			total += r.evidenceBytes
			holding = append(holding, r)
		}
	}
	if total <= allowlist.MaxSandboxVariableEvidenceBytes {
		return
	}
	rank := func(r *record) int {
		rank := 0
		if needed == nil || needed(r.container.Digest) {
			rank += 2
		}
		if len(r.running) > 0 {
			rank++
		}
		return rank
	}
	slices.SortFunc(holding, func(a, b *record) int {
		return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a.seq, b.seq))
	})
	for _, r := range holding {
		if total <= allowlist.MaxSandboxVariableEvidenceBytes {
			return
		}
		total -= r.evidenceBytes
		r.evidenceBytes = 0
		r.container.Env.VariableDigests = nil
		r.container.Env.VariableDigestsEvicted = true
	}
}

func compareObservedMounts(a, b allowlist.ObservedMount) int {
	order := cmp.Or(
		cmp.Compare(a.Destination, b.Destination),
		cmp.Compare(a.Class, b.Class),
		cmp.Compare(a.Storage, b.Storage),
		cmp.Compare(a.HostSourceDigest, b.HostSourceDigest),
		cmp.Compare(a.Provenance, b.Provenance),
		cmp.Compare(a.VerityDigest, b.VerityDigest),
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
// An unresolved container makes the entire snapshot unavailable. Records whose
// image needed reports not needing per-variable env digests carry the
// aggregate digest alone; a nil needed keeps every record's digests.
func (h History) Snapshot(needed func(digest string) bool) ([]string, []workloadclaims.SandboxContainer, error) {
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
		if c.Env != nil && needed != nil && !needed(c.Digest) {
			c.Env.VariableDigests = nil
			c.Env.VariableDigestsEvicted = false
		}
		c.Mounts = slices.Clone(c.Mounts)
		containers = append(containers, c)
	}
	slices.Sort(digests)
	slices.SortFunc(containers, workloadclaims.SandboxContainer.Compare)
	return slices.Compact(digests), containers, nil
}
