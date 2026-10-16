package routing

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

var (
	// ErrNotApplied reports that no manifest has been applied yet (A2).
	ErrNotApplied = errors.New("no route manifest applied")
	// ErrStale reports that the applied manifest outlived its maxAgeSeconds
	// without a refresh (F1).
	ErrStale = errors.New("applied route manifest is stale")
)

// Applied is a manifest the router routes by: the verified signed manifest,
// its parsed form and its compiled table. It is immutable.
type Applied struct {
	Signed   *routes.Signed
	Manifest *routes.Manifest
	Table    *routes.Table
}

// Outcome says what accepting a verified signed manifest did.
type Outcome int

const (
	// OutcomeApplied: the manifest replaced the applied one.
	OutcomeApplied Outcome = iota + 1
	// OutcomeUnchanged: the manifest is the applied one; only freshness moved
	// (F3).
	OutcomeUnchanged
	// OutcomeStaged: the manifest is newer but its notBefore is in the future,
	// so the applied one stays while freshness moves (A4).
	OutcomeStaged
)

// CASource returns the router's currently trusted mesh CAs. It is called on
// every backend handshake and every accepted manifest, so a rotated bundle
// takes effect without a restart.
type CASource func() ([]*x509.Certificate, error)

// StateConfig configures a State.
type StateConfig struct {
	// Reserved lists the paths of the router's protocol endpoints and
	// built-in routes, which no manifest route may shadow (M6).
	Reserved []string
	// MeshCAs are the CAs no address backend may anchor to (B3).
	MeshCAs CASource
	// Now is the clock freshness is measured by. Nil means time.Now.
	Now func() time.Time
}

// State is the router's route state: the applied manifest, at most one
// staged manifest waiting for its notBefore (A4), and the last refresh (F1).
// Its readers are lock-free and see one applied manifest per load (A5). It
// lives in memory, so after a restart any validly signed revision is
// accepted (Q1). It is safe for concurrent use.
type State struct {
	reserved []string
	meshCAs  CASource
	now      func() time.Time

	mu     sync.Mutex     // serializes Accept and guards staged
	staged *routes.Signed // accepted, waiting for its notBefore
	snap   atomic.Pointer[snapshot]
}

// snapshot pairs the applied manifest with the last refresh so a reader never
// judges freshness by one manifest's maxAge and another's fetch time.
type snapshot struct {
	applied   *Applied // nil before the first apply
	refreshed time.Time
}

// NewState returns a State with no manifest applied.
func NewState(cfg StateConfig) *State {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &State{reserved: cfg.Reserved, meshCAs: cfg.MeshCAs, now: now}
}

// Current returns the applied manifest, or nil before the first apply.
func (s *State) Current() *Applied {
	if snap := s.snap.Load(); snap != nil {
		return snap.applied
	}
	return nil
}

// Session returns the manifest a new attested session would be bound to. It
// fails with ErrNotApplied before the first apply, even while a manifest is
// staged (A2), and with ErrStale while the applied manifest is stale (F2);
// with ErrStale it still returns the applied manifest.
func (s *State) Session() (*Applied, error) {
	snap := s.snap.Load()
	switch {
	case snap == nil || snap.applied == nil:
		return nil, ErrNotApplied
	case s.stale(snap):
		return snap.applied, ErrStale
	}
	return snap.applied, nil
}

// Stale reports whether the applied manifest outlived its maxAgeSeconds
// since the last refresh (F1). It is false before the first apply.
func (s *State) Stale() bool { return s.stale(s.snap.Load()) }

func (s *State) stale(snap *snapshot) bool {
	return snap != nil && snap.applied != nil && s.now().Sub(snap.refreshed) >= snap.applied.Manifest.MaxAge
}

// Accept verifies env under keys and the current mesh CAs (W2, B3), then
// applies W4 against the highest accepted revision: the staged manifest while
// one is held, else the applied one (A3). Refetching the applied revision
// while a manifest is staged therefore fails W4 and keeps the staged one.
//
// On success Accept renews freshness (F1, F3), even when env is not yet due
// (A4), and stages it unless it is the manifest already held. A staged
// manifest is applied at the first Accept at or after its notBefore, never
// from a timer. On any error the State is unchanged (A6).
func (s *State) Accept(env routes.Envelope, keys []*ecdsa.PublicKey) (Outcome, error) {
	cas, err := s.meshCAs()
	if err != nil {
		return 0, fmt.Errorf("load mesh CAs: %w", err)
	}
	signed, err := routes.VerifySigned(env, keys, cas)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	cur := s.Current()
	// A staged refresh keeps the applied manifest, so recheck its anchors: a
	// mesh CA rotated into an applied address backend's ca then blocks every
	// refresh, and the applied manifest goes stale (B3, F1).
	if cur != nil && now.Before(signed.Manifest().NotBefore) {
		if err := cur.Manifest.CheckAnchorsExclude(cas); err != nil {
			return 0, fmt.Errorf("applied manifest: %w", err)
		}
	}
	held := s.staged
	if held == nil && cur != nil {
		held = cur.Signed
	}
	if held != nil {
		if err := signed.Supersedes(held.Manifest().Revision, held.Digest()); err != nil {
			return 0, err
		}
	}
	if held == nil || signed.Digest() != held.Digest() {
		s.staged = signed
	}
	outcome := OutcomeUnchanged
	if p := s.staged; p != nil {
		outcome = OutcomeStaged
		if !now.Before(p.Manifest().NotBefore) {
			m := p.Manifest()
			cur = &Applied{Signed: p, Manifest: m, Table: routes.Compile(m, s.reserved)}
			s.staged = nil
			outcome = OutcomeApplied
		}
	}
	s.snap.Store(&snapshot{applied: cur, refreshed: now})
	return outcome, nil
}
