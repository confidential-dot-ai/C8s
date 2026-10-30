// Package cdsha replicates the state a CDS cluster agrees on: its mesh CA,
// the image sets its operator decreed, and the allowlist, secrets and sandbox
// bindings a single CDS keeps for itself. Every replica applies the same log
// through the same state machine, so they answer alike.
//
// The log is the only history of that state. It lives in the replicas' TEE
// memory, and so does everything here.
package cdsha

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// EntryKind names what a log entry changes.
type EntryKind string

// The log entry kinds.
const (
	KindAllowlist EntryKind = "allowlist"
	KindSecret    EntryKind = "secret"
	KindBinding   EntryKind = "binding"
	KindDecree    EntryKind = "decree"
	// KindDoubt records a Recover decree no replica could confirm.
	KindDoubt  EntryKind = "recover_doubt"
	KindFormat EntryKind = "format"
)

// Entry is one log entry. Exactly one payload is set, the one its kind names.
type Entry struct {
	Kind EntryKind `json:"kind"`
	// Format is the oldest format that can apply the entry (0 is baseFormat).
	// It stays 0 until a release changes what an existing field means; a new
	// field needs no Format, since a replica that does not know it stops.
	Format uint32 `json:"format,omitempty"`
	// SetFormat is the format a KindFormat entry raises the cluster to.
	SetFormat uint32                 `json:"set_format,omitempty"`
	Allowlist *allowlist.Command     `json:"allowlist,omitempty"`
	Secret    *secrets.Command       `json:"secret,omitempty"`
	Binding   *sandboxledger.Command `json:"binding,omitempty"`
	Decree    *DecreeEntry           `json:"decree,omitempty"`
	Doubt     *cdsdecree.Signed      `json:"recover_doubt,omitempty"`
}

// Result is what applying one entry produced: the answer of the store command
// or the decree it carried, and the stop it caused. At most one answer is
// set, the one the entry's kind names.
type Result struct {
	Allowlist *allowlist.Result   `json:"allowlist,omitempty"`
	Secret    *secrets.Result     `json:"secret,omitempty"`
	Binding   *sandboxledger.Held `json:"binding,omitempty"`
	Decree    *DecreeResult       `json:"decree,omitempty"`
	// Stop is why this replica could not apply the entry and stopped
	// following the log.
	Stop error `json:"-"`
}

// FSM is the replicated state: ClusterState and the mesh CA, and the three stores the
// log writes. Entries apply one at a time, in log order.
type FSM struct {
	stops

	mu   sync.RWMutex
	core ClusterState
	ca   *issuer.CA
	// launch is what this replica booted with. No entry replaces it.
	launch Launch

	allowlist *allowlist.Store
	secrets   *secrets.MemoryStore
	ledger    *sandboxledger.Ledger

	applied atomic.Uint64
	// decrees is the record of applied decrees, newest last.
	decrees []DecreeRecord
	// readable is the newest format this replica reads; no entry changes it.
	readable uint32
}

// NewFSM builds the state machine of a replica that holds no cluster yet,
// over the stores it applies the log to. It panics on a launch no replica can
// serve, since every field of it comes from the measured configuration.
func NewFSM(launch Launch, al *allowlist.Store, sec *secrets.MemoryStore, led *sandboxledger.Ledger) *FSM {
	if err := launch.check(); err != nil {
		panic(err.Error())
	}
	return &FSM{
		core:      ClusterState{ClusterID: launch.ClusterID},
		launch:    launch,
		allowlist: al,
		secrets:   sec,
		ledger:    led,
		readable:  Format,
	}
}

// ClusterState is a copy of the agreed cluster state.
func (f *FSM) ClusterState() ClusterState {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.core.clone()
}

// CA is the mesh CA, or nil before Genesis.
func (f *FSM) CA() *issuer.CA {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.ca
}

// AppliedIndex is the last log index this replica applied. It moves even for
// an entry the replica stopped on, as Raft has moved on either way.
func (f *FSM) AppliedIndex() uint64 {
	return f.applied.Load()
}

// Apply applies the log entry at index. Entries apply one at a time, in log
// order.
func (f *FSM) Apply(index uint64, entry []byte) Result {
	defer f.applied.Store(index)
	// Deferred in this order, so the command's return is recorded (LIFO)
	// before endStall reads it.
	defer f.endStall()
	defer f.began()()

	var e Entry
	if err := decodeEntry(entry, &e); err != nil {
		return Result{Stop: f.stop(fmt.Errorf("decode log entry %d: %w", index, err))}
	}
	if format := cmp.Or(e.Format, baseFormat); format > f.readable {
		return Result{Stop: f.stop(fmt.Errorf("%w: entry %d needs format %d, and this replica reads up to %d", ErrNewerFormat, index, format, f.readable))}
	}
	res := f.applyRecovering(index, e)
	// The entry is committed, and the replicas whose stores took it hold it.
	// One that could not write it here must not serve on as if it had.
	if res.Allowlist != nil && res.Allowlist.LocalStoreFault() {
		res.Stop = f.stopLocal(fmt.Errorf("log entry %d: this replica's allowlist store: %s", index, res.Allowlist.Message))
	}
	return res
}

// applyRecovering applies e, turning a panic into a deterministic stop: the
// same entry panics on every replica, and a crash would end them all.
func (f *FSM) applyRecovering(index uint64, e Entry) (res Result) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("cds-ha: panic applying a log entry", "index", index, "kind", e.Kind, "panic", p, "stack", string(debug.Stack()))
			res = Result{Stop: f.stop(fmt.Errorf("log entry %d of kind %q panicked: %v", index, e.Kind, p))}
		}
	}()
	return f.apply(e)
}

func (f *FSM) apply(e Entry) Result {
	if err := f.checkEstablishedPolicy(e); err != nil {
		return Result{Stop: f.stop(err)}
	}
	switch {
	case e.Kind == KindAllowlist && e.Allowlist != nil:
		res := f.allowlist.Apply(*e.Allowlist)
		return Result{Allowlist: &res}
	case e.Kind == KindSecret && e.Secret != nil:
		res := f.secrets.Apply(*e.Secret)
		return Result{Secret: &res}
	case e.Kind == KindBinding && e.Binding != nil:
		held := f.ledger.Apply(*e.Binding)
		return Result{Binding: &held}
	case e.Kind == KindDecree && e.Decree != nil:
		return f.applyDecree(*e.Decree)
	case e.Kind == KindDoubt && e.Doubt != nil:
		return f.applyDoubt(*e.Doubt)
	case e.Kind == KindFormat && e.SetFormat != 0:
		return f.applySetFormat(e.SetFormat)
	}
	return Result{Stop: f.stop(fmt.Errorf("malformed log entry of kind %q", e.Kind))}
}

// decodeEntry decodes exactly one JSON value into v, refusing fields v does
// not have: a replica that dropped a field it does not know would apply
// something else than the replicas that know it.
func decodeEntry(entry []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(entry))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("more than one JSON value")
	}
	return nil
}

func (f *FSM) applyDecree(de DecreeEntry) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	if de.kind() == cdsdecree.Genesis {
		// The policy a Genesis fixes must be this replica's own, or it could
		// not apply the commands the cluster then admits.
		if err := f.checkPolicy(de.Policy); err != nil {
			return Result{Stop: f.stop(err)}
		}
	}
	next, ca, err := nextCore(f.launch, f.core, de)
	if err != nil {
		return f.refused(err)
	}
	if next.StartedAtMS > f.core.StartedAtMS {
		if err := f.raiseAllowlistVersion(next.StartedAtMS); err != nil {
			return f.refused(err)
		}
	}
	f.record(de.Decree, de.AtMS, next.Version)
	f.core = next
	if ca != nil {
		f.ca = ca
	}
	return Result{
		Decree: &DecreeResult{Version: next.Version},
	}
}

// refused leaves the cluster as it was (f.mu held).
func (f *FSM) refused(err error) Result {
	return Result{
		Decree: &DecreeResult{
			Version: f.core.Version,
			Refused: err.Error(),
		},
	}
}

// raiseAllowlistVersion moves the served allowlist version to the cluster's
// start time, which the log carries, so every replica serves the same one.
//
// INVARIANT: the served version never decreases across a restart, as long as
// the operator signs the start decree after the earlier life's highest
// version. Node enforcers ignore a version below the one they hold, so a
// version that went back would keep every later write, revocations included,
// from the nodes.
func (f *FSM) raiseAllowlistVersion(startedAtMS int64) error {
	version, err := f.allowlist.RaiseVersion(startedAtMS)
	if err != nil {
		return f.stopLocal(fmt.Errorf("raise the allowlist version to the cluster's start: %w", err))
	}
	slog.Info("cds-ha: the cluster started; the allowlist version is raised to its start time", "version", version, "started_at_ms", startedAtMS)
	return nil
}

// applyDoubt records a Recover decree a leader saw signed while the member it
// names was not healthy here. The doubt belongs to the log: it outlives the
// leader that saw the decree and a host that withholds it from the next one.
func (f *FSM) applyDoubt(sd cdsdecree.Signed) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := cdsdecree.Verify(sd, f.launch.OperatorKeys, f.launch.ClusterID); err != nil {
		return f.refused(err)
	}
	d := sd.Decree
	if d.Kind != cdsdecree.Recover {
		return f.refused(fmt.Errorf("a %s decree raises no doubt", d.Kind))
	}
	if f.core.dealtWith(d.IntentID) {
		return Result{
			Decree: &DecreeResult{Version: f.core.Version},
		}
	}
	f.core.Doubts = append(f.core.Doubts, Doubt{
		Intent: d.IntentID,
		Member: d.TargetMember,
	})
	slog.Error("cds-ha: ALARM: a Recover decree names a member this cluster cannot account for; no replica serves until that member rejoins or the operator dismisses the Recover",
		"intent", d.IntentID, "member", d.TargetMember)
	return Result{
		Decree: &DecreeResult{Version: f.core.Version},
	}
}

// DecreeRecord is one applied decree: what the operator signed, when the
// leader applied it, and the version it produced.
type DecreeRecord struct {
	Decree  cdsdecree.Signed `json:"decree"`
	AtMS    int64            `json:"at_ms"`
	Version uint64           `json:"version"`
}

// maxDecreeRecord bounds the record; older decrees fall off the front.
const maxDecreeRecord = 256

// record appends to the decree record (f.mu held).
func (f *FSM) record(sd cdsdecree.Signed, atMS int64, version uint64) {
	f.decrees = append(f.decrees, DecreeRecord{
		Decree:  sd,
		AtMS:    atMS,
		Version: version,
	})
	if over := len(f.decrees) - maxDecreeRecord; over > 0 {
		f.decrees = slices.Clone(f.decrees[over:])
	}
}

// Decrees is the record of applied decrees, oldest first: the audit trail an
// operator reads over the attested channel, since the decree objects on the
// board are only the host's word.
func (f *FSM) Decrees() []DecreeRecord {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return slices.Clone(f.decrees)
}
