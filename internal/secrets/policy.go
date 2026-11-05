package secrets

import (
	"context"

	"github.com/confidential-dot-ai/c8s/internal/snapshotcache"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// allowlistStore is the persistent allowlist, as internal/allowlist.Store
// implements it.
type allowlistStore interface {
	Version() (string, error)
	LoadAll() (*pkgallowlist.Allowlist, string, error)
}

type policyKey struct {
	generation uint64
	version    string
}

// CachedPolicy publishes an immutable allowlist per local store generation.
// One refresh owner pays the full LoadAll cost after a mutation or restore;
// unchanged production reads only check atomic values.
type CachedPolicy struct {
	store allowlistStore
	cache snapshotcache.Cache[policyKey, *pkgallowlist.Allowlist]
}

func NewCachedPolicy(store allowlistStore) *CachedPolicy { return &CachedPolicy{store: store} }

// Allowlist returns an immutable document. Production stores publish an atomic
// generation, so warm reads need neither a mutex nor a database round trip.
// Unlike a persisted version, the generation also changes when a snapshot with
// the same version is restored. The fallback retains Version error handling for
// other implementations of allowlistStore.
func (c *CachedPolicy) Allowlist() (*pkgallowlist.Allowlist, error) {
	if remote, ok := c.store.(interface{ CanCachePolicy() bool }); ok && !remote.CanCachePolicy() {
		document, _, err := c.store.LoadAll()
		return document, err
	}
	return c.cache.Load(context.Background(), func() (policyKey, error) {
		if source, ok := c.store.(interface{ Generation() uint64 }); ok {
			return policyKey{generation: source.Generation()}, nil
		}
		version, err := c.store.Version()
		return policyKey{version: version}, err
	}, func() (*pkgallowlist.Allowlist, error) {
		document, _, err := c.store.LoadAll()
		return document, err
	})
}
