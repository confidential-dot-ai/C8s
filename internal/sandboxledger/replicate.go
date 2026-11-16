package sandboxledger

import (
	"encoding/binary"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/lthash"
	"github.com/confidential-dot-ai/c8s/internal/replicate"
)

// Held reports whether a binding holds at the CDS that recorded it: false
// means a different, unexpired inventory owns the sandbox, or the ledger had
// no room for it.
type Held bool

// Committer takes one binding: a single CDS applies it, a CDS HA replica
// commits it to the cluster's log first. Commit answers what applying the
// command produced at this CDS, not at the one that ordered it.
type Committer interface {
	replicate.Committer[Command, Held]
	// CatchUp applies what the cluster has committed, as far as it gets, so a
	// binding just taken at another replica is visible here.
	CatchUp()
}

// Handle is the ledger as its callers hold it. It is the only way to record,
// so no path asks which kind of CDS it serves.
type Handle struct {
	ledger *Ledger
	commit Committer
}

// Local is a handle whose bindings apply to the ledger itself.
func (l *Ledger) Local() *Handle {
	return &Handle{
		ledger: l,
		commit: localLedger{Committer: replicate.Local[Command, Held](l)},
	}
}

// CommittedBy is a handle whose bindings c commits to a CDS HA cluster before
// any replica applies them.
func (l *Ledger) CommittedBy(c Committer) *Handle {
	return &Handle{
		ledger: l,
		commit: c,
	}
}

// localLedger is the one ledger that holds every command it commits, so there
// is nothing to catch up with.
type localLedger struct {
	replicate.Committer[Command, Held]
}

func (localLedger) CatchUp() {
}

// Command is one binding, stamped with the clock of the CDS that took it: its
// expiry and first-write-wins follow that clock.
type Command struct {
	SandboxID string `json:"sandbox_id"`
	Host      string `json:"host"`
	AtMS      int64  `json:"at_ms"`
}

// Binding is one entry of a CDS HA snapshot.
type Binding struct {
	SandboxID string `json:"sandbox_id"`
	Host      string `json:"host"`
	ExpiresMS int64  `json:"expires_ms"`
}

// Dump is every binding the ledger holds, expired ones included: a replica
// drops a binding only when a command needs its room, so every replica holds
// the same set.
func (l *Ledger) Dump() []Binding {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Binding, 0, len(l.bindings))
	for id, b := range l.bindings {
		out = append(out, Binding{
			SandboxID: id,
			Host:      b.host,
			ExpiresMS: b.expires.UnixMilli(),
		})
	}
	return out
}

// Restore replaces every binding the ledger holds with a snapshot's.
func (l *Ledger) Restore(bindings []Binding) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bindings = make(map[string]binding, len(bindings))
	l.digest = lthash.Hash{}
	for _, b := range bindings {
		l.setLocked(
			b.SandboxID,
			binding{
				host:    b.Host,
				expires: time.UnixMilli(b.ExpiresMS),
			},
		)
	}
}

// Ledgers that hold the same bindings have the same digest, whatever order
// they took them in.
func (l *Ledger) Digest() [32]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.digest.Sum()
}

// The digest a ledger restored from bindings holds.
func DigestOf(bindings []Binding) [32]byte {
	var digest lthash.Hash
	for _, b := range bindings {
		digest.Add(bindingDigest(
			b.SandboxID,
			binding{
				host:    b.Host,
				expires: time.UnixMilli(b.ExpiresMS),
			},
		))
	}
	return digest.Sum()
}

func bindingDigest(sandboxID string, b binding) [32]byte {
	expires := binary.BigEndian.AppendUint64(nil, uint64(b.expires.UnixMilli()))
	return lthash.Element([]byte(sandboxID), []byte(b.host), expires)
}

// Apply records a binding at the command's time, so every replica judges its
// expiry and the ledger's capacity the same way.
func (l *Ledger) Apply(cmd Command) Held {
	return l.recordAt(time.UnixMilli(cmd.AtMS), cmd.SandboxID, cmd.Host)
}

// Record binds sandboxID to inventoryHost, reporting whether the binding
// holds (see recordAt).
//
// A caller must not deny issuance on false. get-cert has no token-less retry,
// so refusing there would let one pre-claim wedge a pod for a full
// certificate lifetime — a worse outcome than the theft it prevents. False
// means the sandbox is unsafe to answer questions about, not that the
// requester is unauthorized.
func (h *Handle) Record(sandboxID, inventoryHost string) bool {
	held, err := h.commit.Commit(Command{
		SandboxID: sandboxID,
		Host:      inventoryHost,
		AtMS:      h.ledger.now().UnixMilli(),
	})
	if err != nil {
		slog.Warn("sandbox binding not committed; secrets refuse this sandbox until its certificate renews",
			"sandbox_id", sandboxID, "error", err)
		return false
	}
	return bool(held)
}

// Lookup returns the inventory host bound to sandboxID. An expired or absent
// binding reports false, which callers must treat as fail-closed: without it
// there is no inventory this process is willing to believe about the sandbox.
//
// A miss may be a binding another CDS of the cluster took a moment ago
// (issuance there, release here), so it catches up once and looks again.
func (h *Handle) Lookup(sandboxID string) (string, bool) {
	if host, ok := h.ledger.bound(sandboxID); ok {
		return host, true
	}
	h.commit.CatchUp()
	return h.ledger.bound(sandboxID)
}
