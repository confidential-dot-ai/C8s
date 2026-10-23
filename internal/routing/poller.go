package routing

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// firstApplyBackoff is the first retry delay before any manifest is applied.
// Until then every application request fails (A2), so the poller retries
// faster than its interval, doubling up to it.
const firstApplyBackoff = time.Second

// PollerConfig configures a Poller.
type PollerConfig struct {
	State   *State
	Fetcher Fetcher
	Keys    KeySource
	// Transports, when set, is reset when the mesh CA bundle changes and
	// pruned to the backends each applied manifest names. Each poll also
	// refreshes its Entries and retires the pools of workloads whose entry
	// the new allowlist removed or redefined (B10).
	Transports *Transports
	Interval   time.Duration
	Logger     *slog.Logger
}

// Poller fetches the signed manifest from the CDS on an interval and offers
// it to the State.
type Poller struct {
	cfg     PollerConfig
	log     *slog.Logger
	keyHash string
}

// NewPoller returns a Poller. It does not start polling; call Run.
func NewPoller(cfg PollerConfig) *Poller {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{cfg: cfg, log: logger}
}

// Run polls immediately, then every Interval, until ctx is cancelled. A failed
// poll changes nothing (A6) and is retried at the next tick.
func (p *Poller) Run(ctx context.Context) {
	backoff := firstApplyBackoff
	for {
		err := p.Poll(ctx)
		if err != nil && ctx.Err() == nil {
			p.log.Warn("route manifest poll failed; keeping the applied manifest",
				"error", err, "applied", p.cfg.State.Current() != nil, "stale", p.cfg.State.Stale())
		}
		wait := p.cfg.Interval
		if p.cfg.State.Current() == nil && backoff < wait {
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

// refreshEntries reads the current allowlist and retires the pools of the
// workloads whose entry changed since the last poll, including changes a
// dial's reread found. A failed read keeps the allowlist already read and is
// no route poll failure: routes and the allowlist are separate documents.
func (p *Poller) refreshEntries(ctx context.Context, t *Transports) {
	entries := t.cfg.Entries
	if entries == nil {
		return
	}
	before := entries.Digest()
	if err := entries.Refresh(ctx); err != nil && ctx.Err() == nil {
		p.log.Warn("allowlist poll failed; keeping the allowlist already read", "error", err, "read", before != "")
	}
	changed := entries.Changed()
	if after := entries.Digest(); after != before || len(changed) > 0 {
		p.log.Info("allowlist read", "digest", hex.EncodeToString([]byte(after)), "entries_changed", changed)
	}
	t.RetireWorkloads(changed)
}

// Poll fetches the signed manifest once and offers it to the State.
func (p *Poller) Poll(ctx context.Context) (err error) {
	if t := p.cfg.Transports; t != nil {
		if err := t.dropMeshPools(); err != nil {
			return fmt.Errorf("mesh CAs: %w", err)
		}
		// Accept rereads the bundle after a fetch that can be slow. Check it
		// again on the way out, whatever Accept decided.
		defer func() {
			if dropErr := t.dropMeshPools(); dropErr != nil && err == nil {
				err = fmt.Errorf("mesh CAs: %w", dropErr)
			}
		}()
		p.refreshEntries(ctx, t)
	}
	keys, err := p.cfg.Keys.OperatorKeys(ctx)
	if err != nil {
		return fmt.Errorf("operator keys: %w", err)
	}
	if hash, err := operatorauth.KeySetHash(keys); err == nil && hash != p.keyHash {
		p.log.Info("route manifest operator keys loaded", "key_set", hash, "keys", len(keys))
		p.keyHash = hash
	}
	env, err := p.cfg.Fetcher.Routes(ctx)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	outcome, err := p.cfg.State.Accept(env, keys)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	applied := p.cfg.State.Current()
	switch outcome {
	case OutcomeApplied:
		m := applied.Manifest
		digest := applied.Signed.Digest()
		p.log.Info("route manifest applied", "revision", m.Revision,
			"digest", hex.EncodeToString(digest[:]), "hosts", len(m.Hosts))
		if p.cfg.Interval >= m.MaxAge/2 {
			p.log.Warn("route poll interval is at least half of maxAgeSeconds; a missed poll can make the applied manifest stale",
				"interval", p.cfg.Interval, "max_age", m.MaxAge)
		}
	case OutcomeStaged:
		p.log.Info("route manifest staged until its notBefore", "applied", applied != nil)
	}
	if p.cfg.Transports != nil && applied != nil {
		p.cfg.Transports.Retain(applied.Manifest)
	}
	return nil
}
