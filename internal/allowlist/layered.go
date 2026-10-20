package allowlist

import (
	"fmt"
	"strconv"
	"sync"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Layered is the allowlist CDS decides on when its seed is the measured node
// image's (--follow-seed). The store holds what operators write and is served
// as the document they signed; the seed is a read-only layer beside it that no
// write reaches. Decisions run on both (Combine), so an operator upload carries
// only application entries and cannot drop C8s's own, and the served document
// stays byte for byte the one an operator signed.
//
// Without a seed layer it is the store alone.
type Layered struct {
	Store *Store

	mu         sync.Mutex
	seed       *pkgallowlist.Allowlist
	seedBytes  []byte // canonical bytes of seed
	seedDigest string // "sha256:<hex>" of seedBytes
	seedGen    uint64
}

// NewLayered returns the layers over store, with no seed layer yet.
func NewLayered(store *Store) *Layered {
	return &Layered{Store: store}
}

// SetSeed replaces the seed layer. Only a seed no one can change may be set:
// the seed admits without an operator token.
func (l *Layered) SetSeed(seed *pkgallowlist.Allowlist) error {
	body, err := seed.Canonical()
	if err != nil {
		return fmt.Errorf("canonicalize allowlist seed: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seed, l.seedBytes, l.seedDigest = seed, body, objectDigest(body)
	l.seedGen++
	return nil
}

// SeedObject returns the seed layer's canonical bytes when digest names them,
// so a verifier holding a leaf stamped with the seed can fetch what it names.
func (l *Layered) SeedObject(digest string) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seed == nil || digest != l.seedDigest {
		return nil, false
	}
	return l.seedBytes, true
}

// SeedDigest returns "sha256:<hex>" of the seed layer, "" without one.
func (l *Layered) SeedDigest() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seedDigest
}

// LoadLayers returns the stored document and its version, from one store
// read, and the seed layer (nil without one).
func (l *Layered) LoadLayers() (stored *pkgallowlist.Allowlist, version string, seed *pkgallowlist.Allowlist, err error) {
	l.mu.Lock()
	seed = l.seed
	l.mu.Unlock()
	stored, version, err = l.Store.LoadAll()
	return stored, version, seed, err
}

// LoadAll returns the document decisions run on, Combine of the two layers.
// Its version names both layers, so a cache keyed on it reloads when either
// changes; it is not the served ETag.
func (l *Layered) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	l.mu.Lock()
	seed, gen := l.seed, l.seedGen
	l.mu.Unlock()
	stored, version, err := l.Store.LoadAll()
	if err != nil {
		return nil, "", err
	}
	return Combine(stored, seed), layeredVersion(version, gen), nil
}

// Version returns the version LoadAll reports, from a single-row read.
func (l *Layered) Version() (string, error) {
	l.mu.Lock()
	gen := l.seedGen
	l.mu.Unlock()
	version, err := l.Store.Version()
	if err != nil {
		return "", err
	}
	return layeredVersion(version, gen), nil
}

func layeredVersion(stored string, seedGen uint64) string {
	if seedGen == 0 {
		return stored
	}
	return stored + "+" + strconv.FormatUint(seedGen, 10)
}

// Generation counts the mutations of both layers. Both counts only grow, so
// their sum changes whenever either layer does.
func (l *Layered) Generation() uint64 {
	l.mu.Lock()
	gen := l.seedGen
	l.mu.Unlock()
	return l.Store.Generation() + gen
}

// Combine returns the document decisions run on: the seed's entries, and each
// stored entry the seed neither names nor replaces (retiredBySeed, the stale
// generated shapes a reseed of the store retires). An entry the seed names is
// the seed's, which the node's NRI base enforces too, so CDS and the node
// decide on the same entry. A nil seed returns stored.
func Combine(stored, seed *pkgallowlist.Allowlist) *pkgallowlist.Allowlist {
	if seed == nil {
		return stored
	}
	seedKeys, overrideKeys := seedKeySets(seed.Workloads)
	out := make(map[string]pkgallowlist.Workload, len(stored.Workloads)+len(seed.Workloads))
	for name, w := range stored.Workloads {
		if retiredBySeed(name, w, seedKeys, overrideKeys) {
			continue
		}
		out[name] = w
	}
	for name, w := range seed.Workloads {
		out[name] = w
	}
	return &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: out}
}
