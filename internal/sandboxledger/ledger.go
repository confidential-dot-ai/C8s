// Package sandboxledger records which node's admission inventory vouched for a
// pod sandbox, so a later decision about that sandbox asks the same inventory
// rather than one the requester names.
//
// A sandbox token carries the host that signed it, and CDS reads that host to
// find the key that verifies the signature. That is sound for issuance — a wrong
// host simply yields a key the signature fails under — but it makes the
// requester the one choosing which inventory is asked. Anything able to answer
// on the inventory port inside the operator's node CIDRs could otherwise sign a
// token for someone else's sandbox ID, be believed about what that sandbox runs,
// and have the answer used to release that sandbox's secrets.
//
// The binding is therefore taken once, at issuance, and is first-write-wins:
// the first inventory to be believed about a sandbox is the only one believed
// about it. See docs/secrets.md.
package sandboxledger

import (
	"sync"
	"time"
)

// binding is what the ledger holds for one sandbox: the node address whose
// inventory vouched for it, and when that stops being believed.
type binding struct {
	host    string
	expires time.Time
}

// Ledger maps a sandbox ID to the inventory that vouched for it.
//
// Entries expire so a ledger cannot outlive the certificates it describes, and
// the total is capped so sandbox churn — or an inventory minting tokens for
// fabricated IDs — cannot grow it without bound. CDS is a single in-memory
// process whose OOM costs the cluster its mesh CA, so an unbounded map here
// would be a denial primitive.
type Ledger struct {
	mu       sync.Mutex
	bindings map[string]binding
	ttl      time.Duration
	max      int
	now      func() time.Time
}

// New builds a ledger. ttl should be the maximum leaf lifetime: a binding is
// only useful while a certificate carrying that sandbox ID could still be
// presented.
func New(ttl time.Duration, max int) *Ledger {
	return &Ledger{
		bindings: make(map[string]binding),
		ttl:      ttl,
		max:      max,
		now:      time.Now,
	}
}

// recordAt binds sandboxID to inventoryHost as of now, reporting whether the
// binding holds. It is first-write-wins: false means a different, unexpired
// host already owns the sandbox, or the ledger is at its cap with nothing to
// reclaim.
//
// The same host re-recording is a refresh, not a conflict: a workload renews
// its certificate on an interval and re-presents the same pair, so once-only
// would refuse a pod its own renewal.
func (l *Ledger) recordAt(now time.Time, sandboxID, inventoryHost string) Held {
	if sandboxID == "" || inventoryHost == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	switch held, ok := l.bindings[sandboxID]; {
	case ok && held.host == inventoryHost:
		// A binding's expiry never moves back, so a command stamped by a clock
		// behind the one that made it keeps the binding.
		l.bindings[sandboxID] = binding{
			host:    inventoryHost,
			expires: later(now.Add(l.ttl), held.expires),
		}
		return true
	case ok && now.Before(held.expires):
		return false
	case !ok && !l.makeRoomLocked(now):
		return false
	}
	l.bindings[sandboxID] = binding{
		host:    inventoryHost,
		expires: now.Add(l.ttl),
	}
	return true
}

// makeRoomLocked reports room for a binding the ledger does not hold yet; at
// the cap it reclaims the bindings expired at now (l.mu held).
func (l *Ledger) makeRoomLocked(now time.Time) bool {
	if len(l.bindings) < l.max {
		return true
	}
	l.dropExpiredLocked(now)
	return len(l.bindings) < l.max
}

// later is the further of two expiry times.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// bound returns the inventory host bound to sandboxID, if the binding is live.
func (l *Ledger) bound(sandboxID string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.bindings[sandboxID]
	if !ok || !l.now().Before(b.expires) {
		return "", false
	}
	return b.host, true
}

// Len reports the number of live bindings, for metrics and tests. It only
// counts: a binding is dropped when a command needs its room, so every
// replica holds the same bindings whatever each one's clock says.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	live := 0
	for _, b := range l.bindings {
		if now.Before(b.expires) {
			live++
		}
	}
	return live
}

// dropExpiredLocked removes the bindings expired at now (l.mu held).
func (l *Ledger) dropExpiredLocked(now time.Time) {
	for id, b := range l.bindings {
		if !now.Before(b.expires) {
			delete(l.bindings, id)
		}
	}
}
