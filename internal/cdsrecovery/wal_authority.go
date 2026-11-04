package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
)

var ErrPolicyChanged = errors.New("recovery: committed release policy changed during attestation; retry")

// Replay binds a release authority to the existing CDS log, not another policy
// head. Machine must be a fresh FSM built from the approved measured launch and
// store limits. It must not be shared with another log/authority. The caller
// owns its stores and closes them only after WALAuthority.Close.
// Store must satisfy objectwal's trusted linearizable-read contract; a complete
// stale history presented to a cold authority is outside that contract.
type Replay struct {
	Store      objectwal.Store
	Machine    *cdsha.FSM
	LaunchFile []byte
	Options    objectwal.Options
}

// WALAuthority releases only after replaying the current committed CDS policy.
// It retains the original immutable enrollment for identity, origins and the
// first process's initialization permission. After Genesis, image approval
// comes exclusively from the shared FSM's current signed PinsDecree.
// There is no optional policy callback, cache-only path or write to the log.
type WALAuthority struct {
	authority *Authority
	wal       *objectwal.Log
	machine   *cdsha.FSM
	launch    []byte
}

func NewWALAuthority(parent context.Context, expected Identity, record, key []byte, signer ed25519.PrivateKey, verifier string, replay Replay) (*WALAuthority, error) {
	hash := sha256.Sum256(replay.LaunchFile)
	if replay.Store == nil || replay.Machine == nil || len(replay.LaunchFile) == 0 || len(replay.LaunchFile) > 1<<20 ||
		hex.EncodeToString(hash[:]) != expected.ConfigSHA256 || replay.Options.Writer != nil {
		return nil, errors.New("recovery: fresh CDS replay machine, trusted store and exact launch file required")
	}
	core := replay.Machine.ClusterState()
	if replay.Machine.AppliedIndex() != 0 || core.Version != 0 || core.Joined() || core.ClusterID != expected.ClusterID {
		return nil, errors.New("recovery: replay machine must start empty in the enrolled cluster")
	}
	a, err := NewAuthority(parent, expected, record, key, signer, verifier)
	if err != nil {
		return nil, err
	}
	wal, err := objectwal.NewWithOptions(a.ctx, readOnlyStore{replay.Store}, replayMachine{replay.Machine}, key,
		expected.Prefix, expected.ClusterID+"/"+expected.ConfigSHA256, replay.Options)
	if err != nil {
		a.Close()
		return nil, err
	}
	return &WALAuthority{authority: a, wal: wal, machine: replay.Machine, launch: bytes.Clone(replay.LaunchFile)}, nil
}

// RestoreWALAuthority opens an original capsule but never takes its image policy
// as current after Genesis. Every release still needs two fresh log reads.
func RestoreWALAuthority(parent context.Context, expected Identity, record []byte, capsule Capsule, wrappingKey []byte, verifier string, replay Replay) (*WALAuthority, error) {
	material, err := openCapsule(expected, record, capsule, wrappingKey)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	signer := ed25519.NewKeyFromSeed(material[32:])
	defer clear(signer)
	return NewWALAuthority(parent, expected, record, material[:32], signer, verifier, replay)
}

func (a *WALAuthority) current(ctx context.Context, origin string) (Target, string, error) {
	if err := a.wal.Sync(ctx); err != nil {
		return Target{}, "", err
	}
	core := a.machine.ClusterState()
	if a.machine.Stuck() != "" || len(core.Doubts) != 0 {
		return Target{}, "", errors.New("recovery: committed CDS state is fenced")
	}
	target := a.authority.targets[origin]
	if !core.Joined() {
		if a.machine.AppliedIndex() != 0 {
			return Target{}, "", errors.New("recovery: committed Genesis is missing")
		}
		return target, "", nil // Only the exact enrolled first process may use this.
	}
	if core.ClusterID != a.authority.identity.ClusterID || core.ConfigSHA256 != a.authority.identity.ConfigSHA256 ||
		core.PinsDecree == nil || core.PinsDecree.Decree.CDSPins == nil {
		return Target{}, "", errors.New("recovery: committed image policy is missing or belongs to another launch")
	}
	pins, err := core.PinsDecree.Decree.CDSPins.WithLaunchFile(a.launch)
	if err != nil {
		return Target{}, "", err
	}
	target.Images = pins.Policy().Images
	return target, core.PinsDecree.Decree.IntentID, nil
}

// Release linearizes at the final fresh head read when its policy still matches
// the one used for attestation. A revocation seen by that read prevents release.
// A concurrent revocation ordered after it may complete before the grant reaches
// its recipient: this is not a promise to recall an already authorized key.
func (a *WALAuthority) Release(ctx context.Context, origin string) (*Grant, error) {
	if _, exists := a.authority.targets[origin]; !exists {
		return nil, errors.New("recovery: replica origin is not approved")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(a.authority.ctx, cancel)
	defer stop()
	release, err := a.authority.gate.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	target, policy, err := a.current(ctx, origin)
	if err != nil {
		return nil, err
	}
	q, err := fetchRecipient(ctx, a.authority.identity, target)
	if err != nil {
		return nil, err
	}
	if policy == "" && !bytes.Equal(a.authority.genesis, requestHash(q)) {
		return nil, errors.New("recovery: only the enrolled initial process may receive a key before committed Genesis")
	}
	_, finalPolicy, err := a.current(ctx, origin)
	if err != nil {
		return nil, err
	}
	if policy != finalPolicy {
		return nil, ErrPolicyChanged
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return seal(q, Material{Key: a.authority.key, AllowGenesis: policy == ""}, a.authority.signer)
}

func (a *WALAuthority) Stats() requestgate.Stats  { return a.authority.Stats() }
func (a *WALAuthority) WALStats() objectwal.Stats { return a.wal.Stats() }

func (a *WALAuthority) Close() {
	a.authority.Close() // Cancel and drain admitted releases before clearing keys.
	a.wal.Close()
}

// Reuse the complete CDS FSM, including signature, version, snapshot and store
// validation. A second policy-only parser could silently disagree with CDS.
type replayMachine struct{ fsm *cdsha.FSM }

func (m replayMachine) Apply(index uint64, data []byte) (any, error) {
	r := m.fsm.Apply(index, data)
	return r, r.Stop
}
func (m replayMachine) Capture() ([]byte, error) {
	return nil, errors.New("recovery: replay is read-only")
}
func (m replayMachine) Restore(data []byte) (uint64, error) {
	err := m.fsm.Install(bytes.NewReader(data))
	return m.fsm.AppliedIndex(), err
}

type readOnlyStore struct{ objectwal.Store }

func (readOnlyStore) Put(context.Context, string, []byte, string) (string, error) {
	return "", errors.New("recovery: release authority cannot write the WAL")
}
