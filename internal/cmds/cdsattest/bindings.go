package cdsattest

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var (
	errBindingsFull       = errors.New("too many attest-lb connections are bound; retry shortly")
	errClientBindingsFull = errors.New("too many attest-lb connections are bound for this client; retry shortly")
)

// Bindings records what the attest-lb handshake on each public connection
// bound. It never sees a connection close: a binding idle past lbBindingIdle
// lapses and refuses its connection, and is dropped only past lbBindingLife,
// once nginx must have closed the connection. It is safe for concurrent use.
type Bindings struct {
	mu        sync.Mutex
	entries   map[string]lbBinding
	perClient map[string]int // client key -> its bindings, lapsed ones included
	idle      time.Duration
	life      time.Duration
	max       int
	maxClient int
	gen       uint64
	now       func() time.Time
}

// lbHandshake is what an attest-lb handshake bound its connection to.
type lbHandshake struct {
	bound routing.Binding
	// servingLeaf is the SHA-256 of the serving leaf the handshake attested,
	// which the connection presents for as long as it stays open.
	servingLeaf [sha256.Size]byte
}

type lbBinding struct {
	lbHandshake
	client   string // "" is charged to no client
	gen      uint64 // distinguishes successive bindings of one connection
	refused  string // the code the connection's requests are refused with
	lastUsed time.Time
	inFlight int
}

func (e lbBinding) idleFor(now time.Time, d time.Duration) bool {
	return e.inFlight == 0 && now.Sub(e.lastUsed) > d
}

// connectionClosed reports whether nginx must have closed e's connection.
func (b *Bindings) connectionClosed(e lbBinding, now time.Time) bool {
	return e.idleFor(now, b.life)
}

// lapses reports whether e has been idle long enough to lapse.
func (b *Bindings) lapses(e lbBinding, now time.Time) bool {
	return e.refused == "" && e.idleFor(now, b.idle)
}

// NewBindings returns an empty store.
func NewBindings() *Bindings {
	return &Bindings{
		entries:   map[string]lbBinding{},
		perClient: map[string]int{},
		idle:      lbBindingIdle,
		life:      lbBindingLife,
		max:       maxLBBindings,
		maxClient: maxLBBindingsPerClient,
		now:       time.Now,
	}
}

// Hold returns connection's binding, or nil for none, and keeps it until
// Release, which restarts its idle lifetime.
func (b *Bindings) Hold(connection string) *routing.HeldBinding {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[connection]
	if ok {
		entry, ok = b.ageLocked(connection, entry)
	}
	if !ok {
		return nil
	}
	entry.inFlight++
	entry.lastUsed = b.now()
	b.entries[connection] = entry
	return &routing.HeldBinding{
		Binding:     entry.bound,
		RefusedWith: entry.refused,
		Refuse:      func(code string) { b.refuse(connection, entry.gen, code) },
		Release:     sync.OnceFunc(func() { b.release(connection) }),
	}
}

// release ends a Hold.
func (b *Bindings) release(connection string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// INVARIANT: a held entry is never dropped, and a rebind keeps its inFlight.
	entry, ok := b.entries[connection]
	if !ok {
		return
	}
	entry.inFlight--
	entry.lastUsed = b.now()
	b.entries[connection] = entry
}

// refuse keeps connection refused with code, unless it is refused already or
// a handshake rebound it since generation gen was held.
func (b *Bindings) refuse(connection string, gen uint64, code string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[connection]
	if !ok || entry.gen != gen || entry.refused != "" {
		return
	}
	entry.refused = code
	b.entries[connection] = entry
}

// servingLeaf returns the SHA-256 of the serving leaf connection's binding
// was attested with, lapsed or not.
func (b *Bindings) servingLeaf(connection string) ([sha256.Size]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[connection]
	return entry.servingLeaf, ok
}

// room reports whether bind would take connection for client.
func (b *Bindings) room(connection, client string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.roomLocked(connection, client)
}

// bind records handshake for connection, replacing any earlier one on it.
func (b *Bindings) bind(connection, client string, handshake lbHandshake) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.roomLocked(connection, client); err != nil {
		return err
	}
	b.gen++
	entry := lbBinding{lbHandshake: handshake, client: client, gen: b.gen, lastUsed: b.now()}
	if old, rebind := b.entries[connection]; rebind {
		b.unchargeLocked(old.client)
		entry.inFlight = old.inFlight
	}
	if client != "" {
		b.perClient[client]++
	}
	b.entries[connection] = entry
	return nil
}

// roomLocked reports whether bind may take connection for client. A live
// binding is never dropped to make room. The caller holds b.mu.
func (b *Bindings) roomLocked(connection, client string) error {
	b.pruneSomeLocked()
	if old, rebind := b.entries[connection]; rebind {
		return b.rebindRoomLocked(old, client)
	}
	return b.newBindingRoomLocked(client)
}

// rebindRoomLocked: a rebind takes no room, but one under another client
// needs that client's share.
func (b *Bindings) rebindRoomLocked(old lbBinding, client string) error {
	if old.client != client && b.clientFullLocked(client) {
		return errClientBindingsFull
	}
	return nil
}

// newBindingRoomLocked: a new binding needs room in its client's share and in
// all; at either bound, every binding is aged before refusing.
func (b *Bindings) newBindingRoomLocked(client string) error {
	if b.clientFullLocked(client) || b.fullLocked() {
		b.pruneLocked()
	}
	switch {
	case b.clientFullLocked(client):
		return errClientBindingsFull
	case b.fullLocked():
		return errBindingsFull
	}
	return nil
}

func (b *Bindings) clientFullLocked(client string) bool {
	return client != "" && b.perClient[client] >= b.maxClient
}

func (b *Bindings) fullLocked() bool {
	return len(b.entries) >= b.max
}

// ageLocked drops entry once nginx must have closed its connection, else
// lapses it once idle past its lifetime. It returns the entry as stored and
// whether it still is. The caller holds b.mu.
func (b *Bindings) ageLocked(connection string, entry lbBinding) (lbBinding, bool) {
	switch now := b.now(); {
	case b.connectionClosed(entry, now):
		delete(b.entries, connection)
		b.unchargeLocked(entry.client)
		return lbBinding{}, false
	case b.lapses(entry, now):
		entry.refused = types.ErrorCodeBindingExpired
		b.entries[connection] = entry
	}
	return entry, true
}

func (b *Bindings) unchargeLocked(client string) {
	if client == "" {
		return
	}
	if b.perClient[client]--; b.perClient[client] <= 0 {
		delete(b.perClient, client)
	}
}

// pruneOnInsert is how many entries an insert ages. Map order varies per
// range, so inserts spread over the store between sweeps.
const pruneOnInsert = 4

func (b *Bindings) pruneSomeLocked() {
	checked := 0
	for connection, entry := range b.entries {
		if checked++; checked > pruneOnInsert {
			return
		}
		b.ageLocked(connection, entry)
	}
}

// prune ages every binding.
func (b *Bindings) prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
}

func (b *Bindings) pruneLocked() {
	for connection, entry := range b.entries {
		b.ageLocked(connection, entry)
	}
}
