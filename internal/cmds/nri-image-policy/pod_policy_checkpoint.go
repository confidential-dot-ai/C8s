package nriimagepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The document is the effective authenticated CDS policy, including its last
// applied version. The outer guest checkpoint binds it to the same CDS trust.
type podPolicyCheckpoint struct {
	Version  uint64          `json:"version"`
	Document json.RawMessage `json:"document"`
	Digest   string          `json:"digest"`
}

func checkpointPodPolicy(snapshot *policySnapshot) (podPolicyCheckpoint, error) {
	if snapshot == nil {
		return podPolicyCheckpoint{}, errors.New("pod recovery has no policy snapshot")
	}
	if snapshot.pulled == nil {
		if snapshot.version != 0 {
			return podPolicyCheckpoint{}, errors.New("pod policy version has no retained document")
		}
		return podPolicyCheckpoint{}, nil
	}
	raw, err := snapshot.pulled.Canonical()
	if err != nil {
		return podPolicyCheckpoint{}, errors.New("cannot checkpoint Pod policy")
	}
	sum := sha256.Sum256(raw)
	return podPolicyCheckpoint{Version: snapshot.version, Document: raw, Digest: hex.EncodeToString(sum[:])}, nil
}

func restorePodPolicy(saved podPolicyCheckpoint) (*policySnapshot, error) {
	if len(saved.Document) == 0 || bytes.Equal(saved.Document, []byte("null")) {
		if saved.Version != 0 || saved.Digest != "" {
			return nil, errors.New("pod policy checkpoint lost its document")
		}
		return newPolicyStore(nil).current(), nil
	}
	sum := sha256.Sum256(saved.Document)
	if hex.EncodeToString(sum[:]) != saved.Digest {
		return nil, errors.New("pod policy checkpoint digest mismatch")
	}
	pulled, err := allowlist.ParseServedJSON(saved.Document)
	if err != nil {
		return nil, errors.New("invalid Pod policy checkpoint document")
	}
	canonical, err := pulled.Canonical()
	if err != nil || !bytes.Equal(canonical, saved.Document) {
		return nil, errors.New("pod policy checkpoint is not canonical")
	}
	return &policySnapshot{index: pulled.BuildIndex(), pulled: pulled, version: saved.Version}, nil
}

// A same-version response may confirm retained policy, but cannot replace it.
// Pod callers hold podMu through validation, checkpoint and installation.
func validatePodPolicyUpdate(current *policySnapshot, pulled *allowlist.Allowlist, version uint64) error {
	if current == nil || pulled == nil {
		return errors.New("pod policy update is missing its document")
	}
	if version < current.version {
		return errors.New("pod policy update rolls back the retained version")
	}
	if version != current.version || current.pulled == nil {
		return nil
	}
	before, err := current.pulled.Canonical()
	if err != nil {
		return errors.New("invalid retained Pod policy")
	}
	after, err := pulled.Canonical()
	if err != nil || !bytes.Equal(before, after) {
		return errors.New("pod policy update changes the retained version")
	}
	return nil
}
