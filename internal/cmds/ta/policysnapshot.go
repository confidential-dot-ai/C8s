package ta

import (
	"fmt"
	"sync"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/types"
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
	c.held = snapshot
	c.gen = gen
	return snapshot, nil
}

// admittedDigests is what the membership gate established about one report:
// the canonical digest of every image it names, and when the first of those
// admissions ends.
type admittedDigests struct {
	digests map[string]struct{}
	// end is zero while a workload entry or a current set lists every reported
	// digest; otherwise a leaf may not outlive it.
	end time.Time
}

// admitDigests is the membership gate: every digest the report carries must be
// admitted at now. It answers for one instant — a set's deadline ends its
// entries without a write — so it is decided per request and never memoized.
func (s *PolicySnapshot) admitDigests(reported []string, now time.Time) (admittedDigests, error) {
	admitted := admittedDigests{digests: make(map[string]struct{}, len(reported))}
	for _, d := range reported {
		digest, err := types.ParseDigest(d)
		if err != nil {
			return admittedDigests{}, fmt.Errorf("container digest %q: %w", d, err)
		}
		end, ok := s.admissionEnd(digest.String(), now)
		if !ok {
			return admittedDigests{}, fmt.Errorf("container image %s is not allowlisted", digest)
		}
		if !end.IsZero() && (admitted.end.IsZero() || end.Before(admitted.end)) {
			admitted.end = end
		}
		admitted.digests[digest.String()] = struct{}{}
	}
	return admitted, nil
}

// admissionEnd reports whether a canonical digest is admitted at now — by a
// workload entry, or by an entry of a component set in force then — and when
// the last set admitting it ends. A workload entry or a current set carries no
// deadline, so the end is zero.
func (s *PolicySnapshot) admissionEnd(digest string, now time.Time) (time.Time, bool) {
	if _, ok := s.members[digest]; ok {
		return time.Time{}, true
	}
	var last time.Time
	for _, set := range s.Allowlist.Components {
		if !set.InForce(now) || !setLists(set, digest) {
			continue
		}
		if set.Current() {
			return time.Time{}, true
		}
		if deadline := set.Retire.Deadline.Time; deadline.After(last) {
			last = deadline
		}
	}
	return last, !last.IsZero()
}

// setLists reports whether an entry of the set declares digest.
func setLists(set pkgallowlist.ComponentSet, digest string) bool {
	for _, entry := range set.Entries {
		for _, d := range entry.Digests() {
			if d.String() == digest {
				return true
			}
		}
	}
	return false
}
