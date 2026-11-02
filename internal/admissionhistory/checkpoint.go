package admissionhistory

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const maxCheckpointBytes = 8 << 20

type historyCheckpoint struct {
	Version    uint64             `json:"version"`
	Sequence   uint64             `json:"sequence"`
	Records    []checkpointRecord `json:"records"`
	Unresolved []string           `json:"unresolved"`
}

type checkpointRecord struct {
	Container checkpointContainer `json:"container"`
	Sequence  uint64              `json:"sequence"`
	Running   []string            `json:"running"`
}

// No omitempty: unavailable and observed-empty values must survive unchanged.
type checkpointContainer struct {
	Env    *allowlist.EnvObservation `json:"env"`
	Mounts []checkpointMount         `json:"mounts"`
	Digest string                    `json:"digest"`
	Role   string                    `json:"role"`
	Argv   []string                  `json:"argv"`
}

// Local retained state also needs the fields omitted by the node wire profile.
type checkpointMount struct {
	allowlist.ObservedMount
	Source string `json:"source"`
	Volume string `json:"volume"`
}

func checkpointObservation(c workloadclaims.SandboxContainer) checkpointContainer {
	var mounts []checkpointMount
	if c.Mounts != nil {
		mounts = make([]checkpointMount, len(c.Mounts))
		for i, m := range c.Mounts {
			mounts[i] = checkpointMount{ObservedMount: m, Source: m.Source, Volume: m.Volume}
		}
	}
	return checkpointContainer{Env: c.Env, Mounts: mounts, Digest: c.Digest, Role: c.Role, Argv: c.Argv}
}

func (c checkpointContainer) observation() workloadclaims.SandboxContainer {
	var mounts []allowlist.ObservedMount
	if c.Mounts != nil {
		mounts = make([]allowlist.ObservedMount, len(c.Mounts))
		for i, m := range c.Mounts {
			mounts[i] = m.ObservedMount
			mounts[i].Source, mounts[i].Volume = m.Source, m.Volume
		}
	}
	return workloadclaims.SandboxContainer{Env: c.Env, Mounts: mounts, Digest: c.Digest, Role: c.Role, Argv: c.Argv}
}

// Checkpoint preserves cumulative observations and the evidence eviction order.
// Unlike Snapshot, it never filters evidence by the currently served policy.
// The caller must hold its history lock and retain the result in trusted storage.
func (h History) Checkpoint() ([]byte, error) {
	state := historyCheckpoint{Version: 1, Sequence: h.seq, Records: []checkpointRecord{}, Unresolved: []string{}}
	for _, r := range h.byKey {
		running := make([]string, 0, len(r.running))
		for id := range r.running {
			running = append(running, id)
		}
		slices.Sort(running)
		state.Records = append(state.Records, checkpointRecord{Container: checkpointObservation(r.container), Sequence: r.seq, Running: running})
	}
	slices.SortFunc(state.Records, func(a, b checkpointRecord) int {
		return a.Container.observation().Compare(b.Container.observation())
	})
	for id := range h.unresolved {
		state.Unresolved = append(state.Unresolved, id)
	}
	slices.Sort(state.Unresolved)
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > maxCheckpointBytes {
		return nil, errors.New("admission history checkpoint is invalid or too large")
	}
	return raw, nil
}

// RestoreCheckpoint restores guest-retained state, not runtime metadata. It
// validates internal consistency; authenticity belongs to the caller's storage.
// A failure returns no partial history and must prevent recovery.
func RestoreCheckpoint(raw []byte) (History, error) {
	if len(raw) > maxCheckpointBytes || strictjson.Validate(raw) != nil {
		return History{}, errors.New("invalid admission history checkpoint JSON")
	}
	var state historyCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.Version != 1 || state.Records == nil || state.Unresolved == nil {
		return History{}, errors.New("invalid admission history checkpoint fields")
	}
	h := History{byKey: map[string]*record{}, unresolved: map[string]struct{}{}, running: map[string]string{}, seq: state.Sequence}
	sequences := map[uint64]bool{}
	evidenceBytes := 0
	for _, saved := range state.Records {
		c := saved.Container.observation()
		if c.Digest == "" || saved.Sequence == 0 || saved.Sequence > state.Sequence || sequences[saved.Sequence] || saved.Running == nil ||
			(c.Env != nil && !c.Env.Valid()) || !slices.IsSortedFunc(c.Mounts, compareObservedMounts) {
			return History{}, errors.New("invalid admission history checkpoint record")
		}
		sequences[saved.Sequence] = true
		// Record keys omit the eviction marker; evidence can later be restored
		// by another admission of exactly the same environment.
		keyContainer := c
		keyContainer.Env = c.Env.Clone()
		if keyContainer.Env != nil {
			keyContainer.Env.VariableDigests = nil
			keyContainer.Env.VariableDigestsEvicted = false
		}
		key := keyContainer.Key()
		if _, exists := h.byKey[key]; exists {
			return History{}, errors.New("duplicate admission history checkpoint record")
		}
		r := &record{container: c, seq: saved.Sequence, running: map[string]struct{}{}, evidenceBytes: c.Env.VariableEvidenceBytes()}
		evidenceBytes += r.evidenceBytes
		if evidenceBytes > allowlist.MaxSandboxVariableEvidenceBytes {
			return History{}, errors.New("admission history checkpoint exceeds evidence budget")
		}
		for _, id := range saved.Running {
			if _, exists := h.running[id]; id == "" || exists {
				return History{}, errors.New("duplicate or empty admission history container identity")
			}
			h.running[id] = key
			r.running[id] = struct{}{}
		}
		h.byKey[key] = r
	}
	for _, id := range state.Unresolved {
		_, duplicate := h.unresolved[id]
		_, running := h.running[id]
		if id == "" || duplicate || running {
			return History{}, errors.New("inconsistent unresolved admission history identity")
		}
		h.unresolved[id] = struct{}{}
	}
	return h, nil
}
