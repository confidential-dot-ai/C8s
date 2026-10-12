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

// State holds the applied manifest. Its readers are lock-free and see one
// applied manifest per load (A5). It is safe for concurrent use.
type State struct {
	reserved []string
	meshCAs  CASource
	now      func() time.Time

	mu     sync.Mutex   // serializes Accept and guards routes
	routes routes.State // W4, staging and the applied manifest
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
// fails with ErrNotApplied before the first apply (A2) and with ErrStale while
// the applied manifest is stale (F2); with ErrStale it still returns the
// applied manifest.
func (s *State) Session() (*Applied, error) {
	snap := s.snap.Load()
	switch s.status(snap) {
	case routes.Unapplied:
		return nil, ErrNotApplied
	case routes.Stale:
		return snap.applied, ErrStale
	}
	return snap.applied, nil
}

// Status reports whether a manifest is applied and whether it is stale (F1).
func (s *State) Status() routes.Status { return s.status(s.snap.Load()) }

func (s *State) status(snap *snapshot) routes.Status {
	switch {
	case snap == nil || snap.applied == nil:
		return routes.Unapplied
	case s.now().Sub(snap.refreshed) >= snap.applied.Manifest.MaxAge:
		return routes.Stale
	}
	return routes.Fresh
}

// Accept verifies env under keys and the current mesh CAs (W2, B3), then
// records it in the routes.State, which applies W4 against the staged or
// applied manifest (A3) and applies nothing before notBefore (A4). On any
// error the applied manifest and its freshness are unchanged (A6).
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
	changed, err := s.routes.Fetched(signed, now)
	if err != nil {
		return 0, err
	}
	outcome := OutcomeUnchanged
	switch {
	case changed:
		applied := s.routes.Applied()
		m := applied.Manifest()
		cur = &Applied{Signed: applied, Manifest: m, Table: routes.Compile(m, s.reserved)}
		outcome = OutcomeApplied
	case s.routes.Pending() != nil:
		outcome = OutcomeStaged
	}
	s.snap.Store(&snapshot{applied: cur, refreshed: now})
	return outcome, nil
}
