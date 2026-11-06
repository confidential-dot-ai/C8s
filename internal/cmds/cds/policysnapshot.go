package cds

import (
	"fmt"
	"sync"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// PolicySnapshot is one immutable allowlist state a certificate-issuance
// decision runs against: the parsed document, the store version it was read
// at, its canonical bytes, and their SHA-256. Everything a leaf carries about
// the policy — the matched name, the version, the digest — comes from ONE
// snapshot, so a write racing an issuance can never mix two documents into one
// stamp. The version is never read separately from the document.
type PolicySnapshot struct {
	Allowlist *pkgallowlist.Allowlist
	Version   string
	Canonical []byte
	Digest    []byte // SHA-256 of Canonical, 32 bytes

	// members indexes every admitted digest — each workload's init and main
	// containers — for the membership gate.
	members map[string]struct{}
}

// policyStore is the persistent allowlist as the snapshot loader needs it,
// satisfied by *internal/allowlist.Store. LoadAll returns the document and its
// version from one read under the store lock, which is what makes the snapshot
// atomic.
type policyStore interface {
	LoadAll() (*pkgallowlist.Allowlist, string, error)
}

// NewPolicySnapshot builds a validated snapshot from one LoadAll result.
func NewPolicySnapshot(al *pkgallowlist.Allowlist, version string) (*PolicySnapshot, error) {
	if al == nil {
		return nil, fmt.Errorf("policy snapshot: nil allowlist")
	}
	if version == "" {
		return nil, fmt.Errorf("policy snapshot: empty store version")
	}
	canonical, err := al.Canonical()
	if err != nil {
		return nil, fmt.Errorf("policy snapshot: canonicalize allowlist: %w", err)
	}
	digest, err := al.CanonicalDigest()
	if err != nil {
		return nil, fmt.Errorf("policy snapshot: digest allowlist: %w", err)
	}
	members := make(map[string]struct{}, len(al.Workloads))
	for _, w := range al.Workloads {
		for _, d := range w.Digests() {
			members[d.String()] = struct{}{}
		}
	}
	return &PolicySnapshot{
		Allowlist: al,
		Version:   version,
		Canonical: canonical,
		Digest:    digest,
		members:   members,
	}, nil
}

// loadPolicySnapshot reads the store exactly once and snapshots the result. An
// unavailable store is an error — issuance fails rather than stamping from
// stale cached authorization state.
func loadPolicySnapshot(store policyStore) (*PolicySnapshot, error) {
	al, version, err := store.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load allowlist: %w", err)
	}
	return NewPolicySnapshot(al, version)
}

// policyGenerationSource is a store that can say whether it has been written
// since a given moment, satisfied by *internal/allowlist.Store. A store without
// it is never memoized.
type policyGenerationSource interface {
	Generation() uint64
}

// policySnapshotCache memoizes the immutable snapshot between allowlist writes.
//
// A snapshot costs a full LoadAll — the store lock, a JSON unmarshal per entry —
// plus a re-marshal and a SHA-256 of the whole document, and /attest needs one
// per request. Nothing about it changes until the store is written, so it is
// built once per generation instead.
//
// Correctness rests on two things. The generation is read BEFORE the load, so a
// write landing during the load leaves the memo tagged with the older
// generation and the next request rebuilds — the cache can waste a load, never
// serve a stale one. And the snapshot's version still comes from the same
// LoadAll that produced the document: the generation only decides whether to
// reuse, and is never mixed into what a leaf is stamped with.
type policySnapshotCache struct {
	mu   sync.Mutex
	held *PolicySnapshot // nil until the first successful load
	gen  uint64
}

// snapshot returns the memoized snapshot, loading one if the store has been
// written since it was built. The lock is held across the load so a burst of
// concurrent issuances collapses onto one LoadAll rather than racing to repeat
// it.
func (c *policySnapshotCache) snapshot(store policyStore) (*PolicySnapshot, error) {
	src, ok := store.(policyGenerationSource)
	if !ok {
		return loadPolicySnapshot(store)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	gen := src.Generation()
	if c.held != nil && c.gen == gen {
		return c.held, nil
	}
	snapshot, err := loadPolicySnapshot(store)
	if err != nil {
		return nil, err
	}
	c.held, c.gen = snapshot, gen
	return snapshot, nil
}

// Contains reports whether a canonical digest string is admitted as any
// workload container — the same question internal/allowlist.Store.Contains
// answers, but against this snapshot rather than a separate store read.
func (s *PolicySnapshot) Contains(digest string) bool {
	_, ok := s.members[digest]
	return ok
}
