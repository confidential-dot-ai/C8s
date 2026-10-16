package routes

import "time"

// State is a router's route state: the applied signed manifest, at most one
// staged manifest waiting for its NotBefore (A4), and the time of the last
// refresh (F1). The zero State has applied nothing. A State is not safe for
// concurrent use.
type State struct {
	applied   *Signed
	staged    *Signed
	refreshed time.Time
}

// Status is what a State lets the router and the automated ingress service
// serve; see the package doc.
type Status int

const (
	// Unapplied means no manifest is applied, even when one is staged (A2).
	Unapplied Status = iota
	// Stale means the applied manifest's MaxAge has passed since the last
	// refresh (F1).
	Stale
	// Fresh means the applied manifest is current.
	Fresh
)

// Applied returns the applied signed manifest, or nil before the first one.
func (st *State) Applied() *Signed { return st.applied }

// Pending returns the staged manifest waiting for its NotBefore, or nil.
func (st *State) Pending() *Signed { return st.staged }

// Fetched records s, which VerifySigned returned for a GET /routes response
// received over TLS that verified the CDS (A1). A manifest from any other
// source must not reach Fetched: it would renew freshness.
//
// Fetched applies W4 against the highest accepted revision: the staged
// manifest while one is held, else the applied one (A3). Fetching the
// applied revision again while a manifest is staged therefore fails W4 and
// keeps the staged one. On rejection Fetched leaves the State unchanged
// (A6). Otherwise it renews freshness (F1, F3), even when s is not yet due
// (A4), and stages s unless it is the manifest already held. It then calls
// advance, and reports whether the applied manifest changed.
func (st *State) Fetched(s *Signed, now time.Time) (bool, error) {
	held := st.staged
	if held == nil {
		held = st.applied
	}
	if held != nil {
		if err := s.Supersedes(held.manifest.Revision, held.digest); err != nil {
			return false, err
		}
	}
	st.refreshed = now
	if held == nil || s.digest != held.digest {
		st.staged = s
	}
	return st.advance(now), nil
}

// advance applies the staged manifest if now is at or after its NotBefore
// (A4), and reports whether the applied manifest changed. Only Fetched calls
// it, so a staged manifest is applied at the first fetch that verifies it at
// or after NotBefore, never from a timer.
func (st *State) advance(now time.Time) bool {
	p := st.staged
	if p == nil || now.Before(p.manifest.NotBefore) {
		return false
	}
	changed := st.applied == nil || st.applied.digest != p.digest
	st.applied, st.staged = p, nil
	return changed
}

// Status reports whether a manifest is applied and, if so, whether it is
// stale at now (F1).
func (st *State) Status(now time.Time) Status {
	switch {
	case st.applied == nil:
		return Unapplied
	case now.Sub(st.refreshed) >= st.applied.manifest.MaxAge:
		return Stale
	}
	return Fresh
}
