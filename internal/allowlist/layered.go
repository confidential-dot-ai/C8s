package allowlist

import (
	"fmt"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Layered is the allowlist CDS decides on: the store, and on a measured node
// image (--seed-layer) the image's seed as a read-only layer beside it. The
// seed is read once at startup and never written to the store, so an upload
// cannot drop it, and GET /allowlist still serves exactly the stored,
// operator-signed document. Without a seed layer it is the store alone.
type Layered struct {
	Store *Store

	seed       *pkgallowlist.Allowlist // nil without a seed layer
	seedBytes  []byte                  // canonical bytes of seed
	seedDigest string                  // "sha256:<hex>" of seedBytes
}

// NewLayered returns store with seed as its fixed seed layer; a nil seed means
// none. Only a seed no one can change may be a layer: it admits without an
// operator token.
func NewLayered(store *Store, seed *pkgallowlist.Allowlist) (*Layered, error) {
	l := &Layered{Store: store}
	if seed == nil {
		return l, nil
	}
	body, err := seed.Canonical()
	if err != nil {
		return nil, fmt.Errorf("canonicalize allowlist seed: %w", err)
	}
	l.seed, l.seedBytes, l.seedDigest = seed, body, objectDigest(body)
	return l, nil
}

// SeedDigest returns "sha256:<hex>" of the seed layer, "" without one.
func (l *Layered) SeedDigest() string { return l.seedDigest }

// SeedObject returns the seed layer's canonical bytes when digest names them.
func (l *Layered) SeedObject(digest string) ([]byte, bool) {
	if l.seed == nil || digest != l.seedDigest {
		return nil, false
	}
	return l.seedBytes, true
}

// LoadLayers returns the stored document and its version from one store read,
// and the seed layer (nil without one).
func (l *Layered) LoadLayers() (stored *pkgallowlist.Allowlist, version string, seed *pkgallowlist.Allowlist, err error) {
	stored, version, err = l.Store.LoadAll()
	return stored, version, l.seed, err
}

// LoadAll returns Combine of both layers at the store's version. The seed is
// fixed, so the store's version and generation name the combination too.
func (l *Layered) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	stored, version, err := l.Store.LoadAll()
	if err != nil {
		return nil, "", err
	}
	return Combine(stored, l.seed), version, nil
}

// Version returns the store's version.
func (l *Layered) Version() (string, error) { return l.Store.Version() }

// Generation returns the store's generation.
func (l *Layered) Generation() uint64 { return l.Store.Generation() }

// Combine returns the document decisions run on: every entry of both layers.
// On a name both hold the seed's entry wins: it is fixed for the boot, and the
// node's NRI base enforces the image's part of it too. A nil seed returns
// stored.
func Combine(stored, seed *pkgallowlist.Allowlist) *pkgallowlist.Allowlist {
	if seed == nil {
		return stored
	}
	out := make(map[string]pkgallowlist.Workload, len(stored.Workloads)+len(seed.Workloads))
	for name, w := range stored.Workloads {
		out[name] = w
	}
	for name, w := range seed.Workloads {
		out[name] = w
	}
	return &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: out}
}
