package cdsattest

import (
	"errors"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/routing"
)

var (
	errBindingsFull       = errors.New("too many attest-lb connections are bound; retry shortly")
	errClientBindingsFull = errors.New("too many attest-lb connections are bound for this client; retry shortly")
)

// Bindings records, per public connection, what the attest-lb handshake that
// arrived on it bound (E5). nginx names the connection (E8) and never reuses
// a name while the connection is open, but the store does not see the close:
// a binding outlives its connection by up to the idle lifetime, which is why
// the lifetime slides on use and expired bindings are pruned. A binding with a
// request in flight never expires: the routing location allows a request far
// longer than the idle lifetime (E7). The routing
// listener reads it through routing.Bindings. It is safe for concurrent use.
type Bindings struct {
	mu        sync.Mutex
	entries   map[string]lbBinding
	perClient map[string]int // client key -> its live bindings
	idle      time.Duration
	max       int
	maxClient int
	gen       uint64
	now       func() time.Time
}

type lbBinding struct {
	routing.Binding
	client   string // the client key charged for the binding
	gen      uint64 // distinguishes successive bindings of one connection
	refused  string // the code a request on the connection was refused with
	lastUsed time.Time
	inFlight int
}

func (e lbBinding) expired(now time.Time, idle time.Duration) bool {
	return e.inFlight == 0 && now.Sub(e.lastUsed) > idle
}

// NewBindings returns an empty store.
func NewBindings() *Bindings {
	return &Bindings{entries: map[string]lbBinding{}, perClient: map[string]int{}, idle: lbBindingIdle, max: maxLBBindings, maxClient: maxLBBindingsPerClient, now: time.Now}
}

// Hold returns the live binding of connection, the code a request on it was
// refused with and the binding's generation, and keeps the binding until
// release, which restarts its idle lifetime. The caller calls release once.
func (b *Bindings) Hold(connection string) (bound routing.Binding, refused string, gen uint64, release func(), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[connection]
	if !ok {
		return routing.Binding{}, "", 0, nil, false
	}
	if entry.expired(b.now(), b.idle) {
		b.dropLocked(connection, entry)
		return routing.Binding{}, "", 0, nil, false
	}
	entry.inFlight++
	entry.lastUsed = b.now()
	b.entries[connection] = entry
	return entry.Binding, entry.refused, entry.gen, func() { b.release(connection) }, true
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
func (b *Bindings) Refuse(connection string, gen uint64, code string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// A handshake that replaced the binding mid-request attested anew; the
	// refusal belongs to the generation the request was checked against.
	if entry, ok := b.entries[connection]; ok && entry.refused == "" && entry.gen == gen {
		entry.refused = code
		b.entries[connection] = entry
	}
}

// room reports whether bind would take connection for client. A connection
// already bound is rebound in place.
func (b *Bindings) room(connection, client string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.roomLocked(connection, client)
}

// bind records binding for connection, replacing the one an earlier handshake
// on it recorded. A live binding is never dropped to admit another (E7).
func (b *Bindings) bind(connection, client string, binding routing.Binding) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.roomLocked(connection, client); err != nil {
		return err
	}
	if old, ok := b.entries[connection]; ok {
		b.perClient[old.client]--
		if b.perClient[old.client] == 0 {
			delete(b.perClient, old.client)
		}
	}
	b.perClient[client]++
	b.gen++
	b.entries[connection] = lbBinding{Binding: binding, client: client, gen: b.gen, lastUsed: b.now(), inFlight: b.entries[connection].inFlight}
	return nil
}

// dropLocked removes connection's binding and its client charge. The caller
// holds b.mu.
func (b *Bindings) dropLocked(connection string, entry lbBinding) {
	delete(b.entries, connection)
	b.perClient[entry.client]--
	if b.perClient[entry.client] <= 0 {
		delete(b.perClient, entry.client)
	}
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
			b.dropLocked(connection, entry)
		}
	}
}

// roomLocked prunes once: a few entries below the bounds, fully only at one,
// since a full sweep per handshake would cost more than the periodic one. A
// rebind takes no room. The client's share is checked before the global
// bound, so one client cannot fill the store (E7). The caller holds b.mu.
func (b *Bindings) roomLocked(connection, client string) error {
	// A rebind takes no room; one under another client key only needs that
	// client's share.
	if old, ok := b.entries[connection]; ok {
		b.pruneSomeLocked()
		if old.client != client && b.perClient[client] >= b.maxClient {
			return errClientBindingsFull
		}
		return nil
	}
	if b.perClient[client] < b.maxClient && len(b.entries) < b.max {
		b.pruneSomeLocked()
		return nil
	}
	b.pruneLocked()
	if b.perClient[client] >= b.maxClient {
		return errClientBindingsFull
	}
	if len(b.entries) >= b.max {
		return errBindingsFull
	}
	return nil
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
			b.dropLocked(connection, entry)
		}
	}
}
