package cdsattest

import (
	"errors"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/routing"
)

var errBindingsFull = errors.New("too many attest-lb connections are bound; retry shortly")

// Bindings records, per public connection, what the attest-lb handshake that
// arrived on it bound (E5). nginx names the connection (E8). The routing
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
	lastUsed time.Time
}

// NewBindings returns an empty store.
func NewBindings() *Bindings {
	return &Bindings{entries: map[string]lbBinding{}, idle: lbBindingIdle, max: maxLBBindings, now: time.Now}
}

// Lookup returns the live binding of connection.
func (b *Bindings) Lookup(connection string) (routing.Binding, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[connection]
	if !ok {
		return routing.Binding{}, false
	}
	if b.now().Sub(entry.lastUsed) > b.idle {
		delete(b.entries, connection)
		return routing.Binding{}, false
	}
	return entry.Binding, true
}

// Touch restarts the idle lifetime of connection's binding.
func (b *Bindings) Touch(connection string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if entry, ok := b.entries[connection]; ok {
		entry.lastUsed = b.now()
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
	b.entries[connection] = lbBinding{Binding: binding, lastUsed: b.now()}
	return nil
}

// roomLocked prunes only at the bound: a full sweep per handshake would cost
// more than the periodic one. The caller holds b.mu.
func (b *Bindings) roomLocked(connection string) bool {
	if _, ok := b.entries[connection]; ok || len(b.entries) < b.max {
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
		if now.Sub(entry.lastUsed) > b.idle {
			delete(b.entries, connection)
		}
	}
}
