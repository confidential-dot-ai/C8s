package cdsha

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
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
	KindRestore   EntryKind = "restore"
)

// Entry is one Raft log entry. Exactly one payload is set.
type Entry struct {
	Kind      EntryKind              `json:"kind"`
	Allowlist *allowlist.Command     `json:"allowlist,omitempty"`
	Secret    *secrets.Command       `json:"secret,omitempty"`
	Binding   *sandboxledger.Command `json:"binding,omitempty"`
	Decree    *DecreeEntry           `json:"decree,omitempty"`
	Restore   *RestoreEntry          `json:"restore,omitempty"`
}

// RestoreEntry restores a backup into a replica that holds no cluster. It is
// the first entry of a restored cluster, so every replica that joins applies
// the same state.
type RestoreEntry struct {
	Decree   SignedDecree `json:"decree"`
	AtMS     int64        `json:"at_ms"`
	Snapshot []byte       `json:"snapshot"`
}

// DecreeEntry applies one operator decree. The leader stamps the time and,
// for Genesis and RotateKey, the new mesh CA, so every replica applies the
// same result; each replica still checks the operator's signature itself.
type DecreeEntry struct {
	Decree   SignedDecree `json:"decree"`
	AtMS     int64        `json:"at_ms"`
	Pins     []string     `json:"pins,omitempty"`      // Genesis: the bootstrap replica's baked pins
	RootCert []byte       `json:"root_cert,omitempty"` // Genesis, RotateKey
	Key      []byte       `json:"key,omitempty"`       // PKCS#8; Genesis, RotateKey
}

// DecreeResult is what applying a decree returned.
type DecreeResult struct {
	Epoch uint64 `json:"epoch"`
	Err   string `json:"err,omitempty"`
}

// FSM is the replicated state: Core and the mesh CA, the allowlist, the
// secrets and the sandbox ledger. Raft applies entries one at a time.
type FSM struct {
	mu   sync.RWMutex
	core Core
	ca   *issuer.CA

	allowlist *allowlist.Store
	secrets   *secrets.MemoryStore
	ledger    *sandboxledger.Ledger

	applied atomic.Uint64
}

// NewFSM builds the state machine over the replica's local stores. pre is
// the pre-Genesis state from the replica's launch configuration.
func NewFSM(pre Core, al *allowlist.Store, sec *secrets.MemoryStore, led *sandboxledger.Ledger) *FSM {
	return &FSM{core: pre, allowlist: al, secrets: sec, ledger: led}
}

// Core returns a copy of the agreed cluster state.
func (f *FSM) Core() Core {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.core.clone()
}

// CA returns the mesh CA, or nil before Genesis.
func (f *FSM) CA() *issuer.CA {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.ca
}

// AppliedIndex is the last log index this replica applied.
func (f *FSM) AppliedIndex() uint64 { return f.applied.Load() }

// Apply implements raft.FSM.
func (f *FSM) Apply(l *raft.Log) any {
	defer f.applied.Store(l.Index)
	if l.Type != raft.LogCommand {
		return nil
	}
	var e Entry
	if err := json.Unmarshal(l.Data, &e); err != nil {
		return fmt.Errorf("decode log entry %d: %w", l.Index, err)
	}
	return f.apply(e)
}

func (f *FSM) apply(e Entry) any {
	switch {
	case e.Kind == KindAllowlist && e.Allowlist != nil:
		return f.allowlist.Apply(*e.Allowlist)
	case e.Kind == KindSecret && e.Secret != nil:
		return f.secrets.Apply(*e.Secret)
	case e.Kind == KindBinding && e.Binding != nil:
		return f.ledger.Apply(*e.Binding)
	case e.Kind == KindDecree && e.Decree != nil:
		return f.applyDecree(*e.Decree)
	case e.Kind == KindRestore && e.Restore != nil:
		return f.applyRestore(*e.Restore)
	}
	return fmt.Errorf("malformed log entry of kind %q", e.Kind)
}

func (f *FSM) applyDecree(de DecreeEntry) DecreeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	next, ca, err := nextCore(f.core, de)
	if err != nil {
		return DecreeResult{Epoch: f.core.Epoch, Err: err.Error()}
	}
	f.core = next
	if ca != nil {
		f.ca = ca
	}
	return DecreeResult{Epoch: next.Epoch}
}

// applyRestore loads an operator backup, checked against the decree that
// names it, into a replica that holds no cluster.
func (f *FSM) applyRestore(re RestoreEntry) DecreeResult {
	cur := f.Core()
	fail := func(err error) DecreeResult { return DecreeResult{Epoch: cur.Epoch, Err: err.Error()} }
	if re.Decree.Decree.Kind != Restore {
		return fail(errors.New("restore entry without a Restore decree"))
	}
	if err := CheckDecree(re.Decree, cur, time.UnixMilli(re.AtMS)); err != nil {
		return fail(err)
	}
	if SnapshotSHA256(re.Snapshot) != re.Decree.Decree.SnapshotSHA256 {
		return fail(errors.New("snapshot differs from the one the decree names"))
	}
	var sn snapshot
	if err := json.Unmarshal(re.Snapshot, &sn); err != nil {
		return fail(fmt.Errorf("decode snapshot: %w", err))
	}
	switch {
	case sn.Core.ClusterID != cur.ClusterID:
		return fail(fmt.Errorf("snapshot is of cluster %q", sn.Core.ClusterID))
	case !bytes.Equal(sn.Core.OperatorPubKey, cur.OperatorPubKey):
		return fail(errors.New("snapshot names another operator key"))
	case !sn.Core.Joined():
		return fail(errors.New("snapshot holds no mesh CA"))
	}
	sn.Core.Epoch++
	sn.Core.AppliedDecrees = append(sn.Core.AppliedDecrees, re.Decree.Decree.IntentID)
	if err := f.restore(sn); err != nil {
		return fail(err)
	}
	return DecreeResult{Epoch: sn.Core.Epoch}
}

// nextCore is the state after decree entry de, or why de does not apply.
func nextCore(cur Core, de DecreeEntry) (Core, *issuer.CA, error) {
	if err := CheckDecree(de.Decree, cur, time.UnixMilli(de.AtMS)); err != nil {
		return Core{}, nil, err
	}
	d := de.Decree.Decree
	next := cur.clone()
	var ca *issuer.CA
	if d.Kind == Genesis || d.Kind == RotateKey {
		var err error
		if ca, err = caFromDER(de.RootCert, de.Key); err != nil {
			return Core{}, nil, err
		}
		next.RootCert = slices.Clone(de.RootCert)
	}
	switch d.Kind {
	case Genesis:
		pins := normalizePins(de.Pins)
		if len(pins) == 0 {
			return Core{}, nil, errors.New("genesis without the bootstrap replica's pins")
		}
		next.Measurements = pins
		next.GenesisAtMS = de.AtMS
	case UpdateMeasurements, RotateKey:
		if len(d.Measurements) > 0 {
			next.Measurements = slices.Clone(d.Measurements)
		}
	}
	next.Epoch++
	next.AppliedDecrees = append(next.AppliedDecrees, d.IntentID)
	return next, ca, nil
}

// snapshot is the whole replicated state.
type snapshot struct {
	Core      Core                    `json:"core"`
	Key       []byte                  `json:"key,omitempty"`
	Allowlist allowlist.Snapshot      `json:"allowlist"`
	Secrets   []secrets.SnapshotEntry `json:"secrets"`
	Bindings  []sandboxledger.Binding `json:"bindings"`
}

// StoreConfiguration implements raft.ConfigurationStore. The state machine
// keeps no membership of its own; seeing configuration entries is what lets
// its applied index pass them, without which Raft refuses to snapshot (so
// backups stall) after a membership change until the next write.
func (f *FSM) StoreConfiguration(index uint64, _ raft.Configuration) {
	f.applied.Store(index)
}

var _ raft.ConfigurationStore = (*FSM)(nil)

// Snapshot implements raft.FSM. Raft calls it between applies, so the
// state captured here is one point of the log.
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	sn := snapshot{Core: f.core.clone()}
	if f.ca != nil {
		key, err := x509.MarshalPKCS8PrivateKey(f.ca.Key)
		if err != nil {
			f.mu.RUnlock()
			return nil, err
		}
		sn.Key = key
	}
	f.mu.RUnlock()
	al, err := f.allowlist.Dump()
	if err != nil {
		return nil, err
	}
	sn.Allowlist, sn.Secrets, sn.Bindings = al, f.secrets.Dump(), f.ledger.Dump()
	body, err := json.Marshal(sn)
	if err != nil {
		return nil, err
	}
	return fsmSnapshot(body), nil
}

// Restore implements raft.FSM: a joining replica takes the leader's state.
func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	var sn snapshot
	if err := json.NewDecoder(rc).Decode(&sn); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	return f.restore(sn)
}

func (f *FSM) restore(sn snapshot) error {
	var ca *issuer.CA
	if sn.Core.Joined() {
		var err error
		if ca, err = caFromDER(sn.Core.RootCert, sn.Key); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
	}
	if err := f.allowlist.Restore(sn.Allowlist); err != nil {
		return fmt.Errorf("snapshot allowlist: %w", err)
	}
	f.secrets.Restore(sn.Secrets)
	f.ledger.Restore(sn.Bindings)
	f.mu.Lock()
	f.core, f.ca = sn.Core, ca
	f.mu.Unlock()
	return nil
}

type fsmSnapshot []byte

func (s fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (fsmSnapshot) Release() {}
