package sandboxledger

import (
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/lthash"
)

// Replicator carries a binding to every CDS replica (CDS HA) and returns the
// result this replica's Apply produced once it is committed.
type Replicator interface {
	ReplicateBinding(cmd Command) (bool, error)
	// CatchUp returns once this replica has applied everything the cluster
	// had committed when it was called, so a binding just taken at another
	// replica is visible here.
	CatchUp() error
}

// SetReplicator makes every later binding a replicated command.
func (l *Ledger) SetReplicator(r Replicator) { l.repl = r }

// Command records one binding at a time every replica uses alike. With CDS
// HA the leader sets AtMS from its own clock, and a command never applies
// before one already applied: expiry trusts the leader's wall clock, as the
// single-replica CDS trusted its own.
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

// lookupReplicated is Lookup for a replica: a miss may be a binding another
// replica took a moment ago (issuance there, release here), so catch up
// with the cluster once and look again. A failed catch-up needs no branch:
// whatever it applied is committed, and what it did not apply stays a miss.
func (l *Ledger) lookupReplicated(sandboxID string) (string, bool) {
	if h, ok := l.lookupLocal(sandboxID); ok {
		return h, true
	}
	_ = l.repl.CatchUp()
	return l.lookupLocal(sandboxID)
}

// Binding is one entry of a snapshot.
type Binding struct {
	SandboxID string `json:"sandbox_id"`
	Host      string `json:"host"`
	ExpiresMS int64  `json:"expires_ms"`
}

// Dump returns every binding, expired ones included. A replica drops them only
// in Apply, at a command's time, so every replica holds the same set.
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
	l.bytes = 0
	l.digest = lthash.Hash{}
	for _, b := range bs {
		l.setLocked(b.SandboxID, binding{host: b.Host, expires: time.UnixMilli(b.ExpiresMS)})
	}
}

// Digest names the ledger's bindings: equal ledgers have equal digests,
// whatever order their writes came in.
func (l *Ledger) Digest() [32]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.digest.Sum()
}

// DigestOf is the Digest a ledger restored from bs has, computed from the
// bindings themselves.
func DigestOf(bs []Binding) [32]byte {
	var h lthash.Hash
	for _, b := range bs {
		h.Add(bindingDigest(b.SandboxID, b.Host, b.ExpiresMS))
	}
	return h.Sum()
}

// bindingDigest is the SHA-256 of one binding, its fields length-prefixed.
func bindingDigest(sandboxID, host string, expiresMS int64) [32]byte {
	h := sha256.New()
	for _, f := range []string{sandboxID, host} {
		_ = binary.Write(h, binary.BigEndian, uint64(len(f)))
		h.Write([]byte(f))
	}
	_ = binary.Write(h, binary.BigEndian, expiresMS)
	return [32]byte(h.Sum(nil))
}
