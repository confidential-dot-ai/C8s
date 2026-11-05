package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
)

// CurrentRecords binds custody to the SAME encrypted current identity record
// used by CDS. Metadata is the trusted freshness/transaction authority; objects
// hold immutable large values. There is no separate release-policy database,
// command history, checkpoint, or caller-supplied authorization callback.
type CurrentRecords struct {
	Metadata   directstate.Metadata
	Objects    objectwal.Store
	Launch     cdsha.Launch
	Policy     cdsha.Policy
	LaunchFile []byte
}

type CurrentAuthority struct {
	authority *Authority
	store     *directstate.Store
	launch    cdsha.Launch
	policy    cdsha.Policy
	file      []byte
}

func NewCurrentAuthority(parent context.Context, expected Identity, record, key []byte, signer ed25519.PrivateKey, verifier string, records CurrentRecords) (*CurrentAuthority, error) {
	hash := sha256.Sum256(records.LaunchFile)
	if records.Metadata == nil || records.Objects == nil || len(records.LaunchFile) == 0 || len(records.LaunchFile) > 1<<20 ||
		hex.EncodeToString(hash[:]) != expected.ConfigSHA256 || records.Launch.ConfigSHA256 != expected.ConfigSHA256 ||
		records.Launch.ClusterID != expected.ClusterID || len(records.Launch.OperatorKeys) == 0 || records.Launch.Voters < 1 {
		return nil, errors.New("recovery: trusted current records and exact enrolled launch required")
	}
	a, err := NewAuthority(parent, expected, record, key, signer, verifier)
	if err != nil {
		return nil, err
	}
	store, err := directstate.New(a.ctx, readOnlyMetadata{records.Metadata}, readOnlyStore{records.Objects}, key, expected.Prefix, expected.ClusterID+"/"+expected.ConfigSHA256)
	if err != nil {
		a.Close()
		return nil, err
	}
	return &CurrentAuthority{authority: a, store: store, launch: records.Launch, policy: records.Policy, file: bytes.Clone(records.LaunchFile)}, nil
}

func RestoreCurrentAuthority(parent context.Context, expected Identity, record []byte, capsule Capsule, wrappingKey []byte, verifier string, records CurrentRecords) (*CurrentAuthority, error) {
	material, err := openCapsule(expected, record, capsule, wrappingKey)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	signer := ed25519.NewKeyFromSeed(material[32:])
	defer clear(signer)
	return NewCurrentAuthority(parent, expected, record, material[:32], signer, verifier, records)
}

func (a *CurrentAuthority) current(ctx context.Context, origin string) (Target, string, error) {
	v, err := a.store.Read(ctx, directstate.IdentityRecord)
	if err != nil {
		return Target{}, "", err
	}
	defer v.Clear()
	target := a.authority.targets[origin]
	data, exists := v.Get(directstate.IdentityRecord)
	if !exists {
		return target, "", nil
	} // Exact enrolled first process only.
	var core cdsha.CurrentCore
	if strictjson.Validate(data) != nil {
		return Target{}, "", objectwal.ErrCorrupt
	}
	err = decode(data, &core)
	defer clear(core.MeshCAKey)
	if err != nil {
		return Target{}, "", objectwal.ErrCorrupt
	}
	if _, err := core.Open(a.launch, a.policy); err != nil {
		return Target{}, "", err
	}
	if core.Core.PinsDecree == nil || core.Core.PinsDecree.Decree.CDSPins == nil {
		return Target{}, "", errors.New("recovery: current signed image policy missing")
	}
	pins, err := core.Core.PinsDecree.Decree.CDSPins.WithLaunchFile(a.file)
	if err != nil {
		return Target{}, "", err
	}
	target.Images = pins.Policy().Images
	return target, core.Core.PinsDecree.Decree.IntentID, nil
}

// Release has the WAL authority's exact linearization rule: fresh current
// policy, fresh attestation, then a second current policy read. A revocation
// ordered after the final read cannot recall a grant already authorized.
func (a *CurrentAuthority) Release(ctx context.Context, origin string) (*Grant, error) {
	return a.authority.releaseCurrent(ctx, origin, a.current)
}

func (a *CurrentAuthority) Stats() requestgate.Stats { return a.authority.Stats() }
func (a *CurrentAuthority) Close() {
	a.authority.Close()
	a.store.Close()
}

type readOnlyMetadata struct{ directstate.Metadata }

func (readOnlyMetadata) Commit(context.Context, metadatapilot.Transaction) error {
	return errors.New("recovery: release authority cannot write current state")
}
