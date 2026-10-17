package sandboxledger

import (
	"log/slog"
	"time"
)

// Replicator carries a binding to every CDS replica (CDS HA) and returns the
// result this replica's Apply produced once it is committed.
type Replicator interface {
	ReplicateBinding(cmd Command) (bool, error)
}

// SetReplicator makes every later binding a replicated command.
func (l *Ledger) SetReplicator(r Replicator) { l.repl = r }

// Command records one binding at a time every replica uses alike.
type Command struct {
	SandboxID string `json:"sandbox_id"`
	Host      string `json:"host"`
	AtMS      int64  `json:"at_ms"`
}

// Apply records a replicated binding. Expiry and the capacity bound are
// judged at the command's time, so every replica decides the same way.
func (l *Ledger) Apply(cmd Command) bool {
	return l.recordAt(time.UnixMilli(cmd.AtMS), cmd.SandboxID, cmd.Host)
}

// recordReplicated writes only what changes the answer: a new binding, or a
// refresh once less than half the lifetime is left, so certificate renewals
// cost at most about two writes per lifetime. A conflict is decided locally:
// the committed binding is already here.
func (l *Ledger) recordReplicated(sandboxID, inventoryHost string) bool {
	now := l.now()
	l.mu.Lock()
	b, ok := l.bindings[sandboxID]
	l.mu.Unlock()
	if ok && now.Before(b.expires) {
		if b.host != inventoryHost {
			return false
		}
		if b.expires.Sub(now) > l.ttl/2 {
			return true
		}
	}
	held, err := l.repl.ReplicateBinding(Command{SandboxID: sandboxID, Host: inventoryHost, AtMS: now.UnixMilli()})
	if err != nil {
		slog.Warn("sandbox binding not replicated; secrets will refuse this sandbox until it renews", "sandbox_id", sandboxID, "error", err)
		return false
	}
	return held
}

// Binding is one entry of a snapshot.
type Binding struct {
	SandboxID string `json:"sandbox_id"`
	Host      string `json:"host"`
	ExpiresMS int64  `json:"expires_ms"`
}

// Dump returns every binding, expired ones included: dropping them is a local
// matter that never changes an answer.
func (l *Ledger) Dump() []Binding {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Binding, 0, len(l.bindings))
	for id, b := range l.bindings {
		out = append(out, Binding{SandboxID: id, Host: b.host, ExpiresMS: b.expires.UnixMilli()})
	}
	return out
}

// Restore replaces the ledger's bindings with a snapshot.
func (l *Ledger) Restore(bs []Binding) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bindings = make(map[string]binding, len(bs))
	for _, b := range bs {
		l.bindings[b.SandboxID] = binding{host: b.Host, expires: time.UnixMilli(b.ExpiresMS)}
	}
}
