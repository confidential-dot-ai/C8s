package secrets

import (
	"sync"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// allowlistStore is the persistent allowlist, as internal/allowlist.Store
// implements it.
type allowlistStore interface {
	Version() (string, error)
	LoadAll() (*pkgallowlist.Allowlist, string, error)
}

// CachedPolicy serves the allowlist to the handler, reloading only when the
// version counter moves.
//
// LoadAll is a full table scan plus a JSON unmarshal per workload entry, and
// every secret request needs the whole document to match a container set
// against it. Version is a single-row read, so the reload cost is paid on an
// operator write rather than on each request.
type CachedPolicy struct {
	store allowlistStore

	mu      sync.Mutex
	version string
	cached  *pkgallowlist.Allowlist
}

// NewCachedPolicy wraps a store.
func NewCachedPolicy(store allowlistStore) *CachedPolicy {
	return &CachedPolicy{store: store}
}

// Allowlist returns the current document.
func (c *CachedPolicy) Allowlist() (*pkgallowlist.Allowlist, error) {
	version, err := c.store.Version()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != nil && c.version == version {
		return c.cached, nil
	}
	// The version read and this load are not atomic, so a write landing between
	// them yields a document newer than the version it is cached under. The
	// next request reloads it, and a stale-by-one-write allowlist is not a
	// safety property here: a grant is checked against whatever document is
	// current at match time, and both are operator-signed.
	al, loadedVersion, err := c.store.LoadAll()
	if err != nil {
		return nil, err
	}
	c.cached, c.version = al, loadedVersion
	return al, nil
}
