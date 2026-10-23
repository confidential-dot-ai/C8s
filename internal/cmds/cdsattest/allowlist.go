package cdsattest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

var (
	// errAllowlistUnavailable: no allowlist fetch has succeeded yet.
	errAllowlistUnavailable = errors.New("no allowlist fetched from the CDS yet")
	// errAllowlistStale: the last successful fetch is older than the maximum
	// age, so the digest may no longer be the one the CDS serves.
	errAllowlistStale = errors.New("the allowlist digest is stale")
)

// defaultAllowlistMaxAge bounds how old the allowlist digest an attested
// handshake binds may be. The tracker polls three times per max age, so two
// polls in a row can fail before handshakes are refused.
const defaultAllowlistMaxAge = 60 * time.Second

// firstFetchBackoff is the first retry delay before any allowlist fetch has
// succeeded.
const firstFetchBackoff = time.Second

// allowlistTracker holds the digest of the allowlist the CDS serves, as of the
// last successful GET /allowlist over the CDS-verified connection. Both
// attested handshakes bind it; once it is older than maxAge they refuse rather
// than report a digest the CDS may have replaced.
type allowlistTracker struct {
	// fetch returns the exact bytes of a 200 GET /allowlist.
	fetch  func(context.Context) ([]byte, error)
	maxAge time.Duration
	now    func() time.Time
	log    *slog.Logger

	last atomic.Pointer[allowlistSnapshot]
}

type allowlistSnapshot struct {
	digest    [sha256.Size]byte
	refreshed time.Time
}

func newAllowlistTracker(fetch func(context.Context) ([]byte, error), maxAge time.Duration, logger *slog.Logger) *allowlistTracker {
	return &allowlistTracker{fetch: fetch, maxAge: maxAge, now: time.Now, log: logger}
}

// Digest returns the digest a new attested handshake binds, or
// errAllowlistUnavailable / errAllowlistStale.
func (t *allowlistTracker) Digest() ([]byte, error) {
	snap := t.last.Load()
	switch {
	case snap == nil:
		return nil, errAllowlistUnavailable
	case t.now().Sub(snap.refreshed) >= t.maxAge:
		return nil, errAllowlistStale
	}
	return snap.digest[:], nil
}

// Poll fetches the allowlist once and records its digest. A failed fetch
// changes nothing; the digest ages until a fetch succeeds. The whole body is
// fetched every time: the CDS version (its entity tag) can repeat with other
// content after a CDS reset, so a 304 would not prove the digest unchanged.
func (t *allowlistTracker) Poll(ctx context.Context) error {
	body, err := t.fetch(ctx)
	if err != nil {
		return err
	}
	snap := &allowlistSnapshot{digest: sha256.Sum256(body), refreshed: t.now()}
	if prev := t.last.Swap(snap); prev == nil || prev.digest != snap.digest {
		t.log.Info("allowlist digest updated", "allowlist_digest", "sha256:"+hex.EncodeToString(snap.digest[:]))
	}
	return nil
}

// Run polls immediately, then three times per maxAge, until ctx is
// cancelled. Before the first success it retries sooner, from one second
// doubling up to the interval, as the route poller does.
func (t *allowlistTracker) Run(ctx context.Context) {
	interval := t.maxAge / 3
	backoff := firstFetchBackoff
	for {
		if err := t.Poll(ctx); err != nil && ctx.Err() == nil {
			_, refused := t.Digest()
			t.log.Warn("allowlist fetch failed; keeping the last digest", "error", err, "refusing_handshakes", refused != nil)
		}
		wait := interval
		if t.last.Load() == nil && backoff < wait {
			wait = backoff + rand.N(backoff/2)
			backoff *= 2
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
