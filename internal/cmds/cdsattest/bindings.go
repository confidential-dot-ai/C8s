package cdsattest

import (
	"errors"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/routing"
)

var errBindingsFull = errors.New("too many attest-lb connections are bound; retry shortly")

// Bindings records, per public connection, what the attest-lb handshake that
// arrived on it bound (E5). nginx names the connection (E8) and never reuses
// a name while the connection is open, but the store does not see the close:
// a binding outlives its connection by up to the idle lifetime, which is why
// the lifetime slides on use and expired bindings are pruned. A binding with a
// request in flight never expires: the routing location allows a request far
// longer than the idle lifetime (E7). The routing
// listener reads it through routing.Bindings. It is safe for concurrent use.
type Bindings struct {
	mu      sync.Mutex
	entries map[string]lbBinding
	idle    time.Duration
	max     int
	now     func() time.Time
}

type lbBinding struct {
	routing.Binding
	refused  string // the code a request on the connection was refused with
	lastUsed time.Time
	inFlight int
}

func (e lbBinding) expired(now time.Time, idle time.Duration) bool {
	return e.inFlight == 0 && now.Sub(e.lastUsed) > idle
}

// NewBindings returns an empty store.
func NewBindings() *Bindings {
	return &Bindings{entries: map[string]lbBinding{}, idle: lbBindingIdle, max: maxLBBindings, now: time.Now}
}

// Hold returns the live binding of connection and the code a request on it
// was refused with, and keeps the binding until release, which restarts its
// idle lifetime. The caller calls release once.
func (b *Bindings) Hold(connection string) (bound routing.Binding, refused string, release func(), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[connection]
	if !ok {
		return routing.Binding{}, "", nil, false
	}
	if entry.expired(b.now(), b.idle) {
		delete(b.entries, connection)
		return routing.Binding{}, "", nil, false
	}
	entry.inFlight++
	entry.lastUsed = b.now()
	b.entries[connection] = entry
	return entry.Binding, entry.refused, func() { b.release(connection) }, true
}

// release ends a Hold. A held entry is never pruned, and a handshake that
// rebinds it keeps its count, so the entry is still there.
func (b *Bindings) release(connection string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.entries[connection]
	entry.inFlight--
	entry.lastUsed = b.now()
	b.entries[connection] = entry
}

// Refuse records that a request on connection was refused with code; only a
// new handshake on the connection clears it (E6).
func (b *Bindings) Refuse(connection string, held routing.Binding, code string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// A handshake that replaced the binding mid-request attested anew; the
	// refusal belongs to the binding the request was checked against.
	if entry, ok := b.entries[connection]; ok && entry.refused == "" && entry.Binding == held {
		entry.refused = code
		b.entries[connection] = entry
	}
}

// room reports whether bind would take connection. A connection already bound
// is rebound in place.
func (b *Bindings) room(connection string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.roomLocked(connection)
}

// bind records binding for connection, replacing the one an earlier handshake
// on it recorded. A live binding is never dropped to admit another (E7).
func (b *Bindings) bind(connection string, binding routing.Binding) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.roomLocked(connection) {
		return errBindingsFull
	}
	b.entries[connection] = lbBinding{Binding: binding, lastUsed: b.now(), inFlight: b.entries[connection].inFlight}
	return nil
}

// pruneOnInsert is how many entries an insert checks for expiry. Map order
// varies per range, so inserts spread over the store between sweeps.
const pruneOnInsert = 4

func (b *Bindings) pruneSomeLocked() {
	now, checked := b.now(), 0
	for connection, entry := range b.entries {
		if checked++; checked > pruneOnInsert {
			return
		}
		if entry.expired(now, b.idle) {
			delete(b.entries, connection)
		}
	}
}

// roomLocked prunes once: a few entries below the bound, fully only at it,
// since a full sweep per handshake would cost more than the periodic one. The
// caller holds b.mu.
func (b *Bindings) roomLocked(connection string) bool {
	if _, ok := b.entries[connection]; ok || len(b.entries) < b.max {
		b.pruneSomeLocked()
		return true
	}
	b.pruneLocked()
	return len(b.entries) < b.max
}

// prune drops the bindings idle past their lifetime.
func (b *Bindings) prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
}

func (b *Bindings) pruneLocked() {
	now := b.now()
	for connection, entry := range b.entries {
		if entry.expired(now, b.idle) {
			delete(b.entries, connection)
		}
	}
}
