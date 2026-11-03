// Package snapshotcache publishes immutable derived views without a read lock.
package snapshotcache

import (
	"context"
	"sync/atomic"
)

type snapshot[K comparable, V any] struct {
	key   K
	value V
}

type refresh struct{ done chan struct{} }

// Cache has one refresh owner. Waiters receive its completion, then recheck
// their own generation: a refresh started before a revocation cannot satisfy a
// later caller without that check. Values must be immutable after publication.
// A Cache belongs to one source for its entire lifetime.
type Cache[K comparable, V any] struct {
	view    atomic.Pointer[snapshot[K, V]]
	loading atomic.Pointer[refresh]
}

// Load checks the source's generation on every call. The source must publish a
// new generation before acknowledging a mutation, including restore and close.
// No IO runs under an application mutex, and an unchanged view takes no lock.
func (c *Cache[K, V]) Load(ctx context.Context, generation func() (K, error), build func() (V, error)) (V, error) {
	var zero V
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		key, err := generation()
		if err != nil {
			return zero, err
		}
		if held := c.view.Load(); held != nil && held.key == key {
			return held.value, nil
		}
		if pending := c.loading.Load(); pending != nil {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-pending.done:
				continue
			}
		}
		owner := &refresh{done: make(chan struct{})}
		if !c.loading.CompareAndSwap(nil, owner) {
			continue
		}
		return c.reload(owner, key, build)
	}
}

func (c *Cache[K, V]) reload(owner *refresh, key K, build func() (V, error)) (V, error) {
	defer func() {
		c.loading.Store(nil)
		close(owner.done)
	}()
	var zero V
	// Another owner may have finished between the first check and our CAS.
	if held := c.view.Load(); held != nil && held.key == key {
		return held.value, nil
	}
	value, err := build()
	if err != nil {
		return zero, err // Never fall back to a view after its generation changed.
	}
	// Tag with the generation BEFORE loading. A concurrent write may make this
	// value newer, but must never tag an older document with a newer generation.
	c.view.Store(&snapshot[K, V]{key: key, value: value})
	return value, nil
}
