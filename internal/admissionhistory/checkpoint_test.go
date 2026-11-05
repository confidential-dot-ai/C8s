package admissionhistory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func restoreHistory(t *testing.T, h History) History {
	t.Helper()
	raw, err := h.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreCheckpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := restored.Checkpoint()
	if err != nil || !bytes.Equal(raw, second) {
		t.Fatalf("checkpoint changed across restore: %v", err)
	}
	return restored
}

// Exited and unresolved admissions survive a restart intact.
func TestCheckpointRetainsCompletedAndUnresolvedAdmissions(t *testing.T) {
	var h History
	h = restoreHistory(t, h)
	envA, _ := allowlist.ObserveEnv([]string{"MODE=a"})
	envB, _ := allowlist.ObserveEnv([]string{"MODE=b"})
	h.Record("init", "sha256:a", "", []string{"run", "init"}, envA, []allowlist.ObservedMount{}...)
	h.Exited("init")
	h.Record("app", "sha256:a", "", []string{"run", "app"}, envB)
	h.Record("unknown", "", "", nil, nil)
	h.Exited("unknown")
	restored := restoreHistory(t, h)
	if _, _, err := restored.Snapshot(nil); err == nil {
		t.Fatal("restoring an exited unresolved admission opened the history")
	}
	for _, history := range []*History{&h, &restored} {
		history.Record("unknown", "sha256:b", "", []string{}, nil)
		history.Bound(nil)
	}
	_, want, _ := h.Snapshot(nil)
	_, got, err := restored.Snapshot(nil)
	if err != nil || len(got) != 3 || !reflect.DeepEqual(got, want) {
		t.Fatalf("restore lost completed or distinct observations: %#v, %v", got, err)
	}
	if _, exists := restored.running["init"]; exists {
		t.Fatal("completed init became running after restore")
	}
	restored = restoreHistory(t, restored)
	_, got, _ = restored.Snapshot(nil)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("restore changed empty argv or mount evidence")
	}
}

// named-volume identities remain distinct in retained history.
func TestCheckpointRetainsNamedVolumeVariants(t *testing.T) {
	var h History
	env, _ := allowlist.ObserveEnv(nil)
	for _, volume := range []string{"first", "second"} {
		h.Record(volume, "sha256:a", "mesh", []string{"run"}, env, allowlist.ObservedMount{
			Destination: "/data", Source: "/run/pod/" + volume, Volume: volume,
			Class: allowlist.MountEmptyDir, Storage: allowlist.MountMemory, ReadOnly: true,
			HostSourceDigest: "commitment", Provenance: "guest",
		})
		h.Exited(volume)
	}
	restored := restoreHistory(t, h)
	_, want, _ := h.Snapshot(nil)
	_, got, err := restored.Snapshot(nil)
	if err != nil || len(got) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("restart lost mount identity or merged named volumes: %#v, %v", got, err)
	}
}

// The evidence a restart retains is the evidence the live history kept.
func TestCheckpointRetainsEvidenceEvictionOrder(t *testing.T) {
	var h History
	fit := allowlist.MaxSandboxVariableEvidenceBytes / observeAtLimits(t, "x").VariableEvidenceBytes()
	for i := range fit + 1 {
		id := fmt.Sprint(i)
		h.Record(id, "sha256:a", "", []string{"run", id}, observeAtLimits(t, id))
		if i%2 == 0 {
			h.Exited(id)
		}
	}
	h.Bound(nil)
	restored := restoreHistory(t, h)
	for _, history := range []*History{&h, &restored} {
		history.Record("next", "sha256:b", "", []string{"run"}, observeAtLimits(t, "next"))
		history.Exited("1")
		history.Bound(nil)
	}
	want, _ := h.Checkpoint()
	got, err := restored.Checkpoint()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("restart changed evidence eviction decisions: %v", err)
	}
}

// An inconsistent checkpoint restores no history at all.
func TestCheckpointRejectsInconsistentHistory(t *testing.T) {
	var h History
	env, _ := allowlist.ObserveEnv(nil)
	h.Record("live", "sha256:a", "", []string{"run"}, env)
	raw, _ := h.Checkpoint()
	cases := map[string]func(*historyCheckpoint){
		"version":         func(s *historyCheckpoint) { s.Version++ },
		"future sequence": func(s *historyCheckpoint) { s.Records[0].Sequence++ },
		"duplicate observation with independent sequence and live ID": func(s *historyCheckpoint) {
			s.Sequence++
			second := s.Records[0]
			second.Sequence = s.Sequence
			second.Running = []string{"second"}
			s.Records = append(s.Records, second)
		},
		"duplicate live ID":   func(s *historyCheckpoint) { s.Records[0].Running = []string{"live", "live"} },
		"invalid environment": func(s *historyCheckpoint) { s.Records[0].Container.Env.Digest = "bad" },
		"running unresolved":  func(s *historyCheckpoint) { s.Unresolved = []string{"live"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var state historyCheckpoint
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			mutate(&state)
			invalid, _ := json.Marshal(state)
			if _, err := RestoreCheckpoint(invalid); err == nil {
				t.Fatal("accepted inconsistent history")
			}
		})
	}
	for _, invalid := range [][]byte{nil, []byte(`{"version":1,"version":1}`)} {
		if _, err := RestoreCheckpoint(invalid); err == nil {
			t.Fatal("accepted ambiguous or incomplete JSON")
		}
	}
}

// History above its storage or evidence bound is refused before it is retained.
func TestCheckpointRefusesOversizedHistoryAndUnboundedEvidence(t *testing.T) {
	t.Run("serialized history", func(t *testing.T) {
		var h History
		payload := strings.Repeat("x", 16<<10)
		state := historyCheckpoint{Version: 1, Unresolved: []string{}}
		// A long-lived Pod can accumulate many individually executable launches.
		// Each argument fits Linux's per-argument limit; their history exceeds
		// the checkpoint bound only cumulatively.
		for i := range maxCheckpointBytes/len(payload) + 1 {
			id := fmt.Sprint(i)
			argv := []string{"run", id, payload}
			h.Record(id, "sha256:a", "", argv, nil)
			state.Sequence++
			state.Records = append(state.Records, checkpointRecord{
				Container: checkpointContainer{Digest: "sha256:a", Argv: argv}, Sequence: state.Sequence, Running: []string{id},
			})
		}
		if raw, err := h.Checkpoint(); err == nil || raw != nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("oversized history produced usable state or the wrong refusal: %v", err)
		}
		// Syntactically valid stored records above the bound must also be
		// refused on restore, before they can become retained authority.
		raw, err := json.Marshal(state)
		if err != nil || len(raw) <= maxCheckpointBytes {
			t.Fatalf("invalid oversized checkpoint fixture: %d bytes, %v", len(raw), err)
		}
		if _, err := RestoreCheckpoint(raw); err == nil {
			t.Fatal("restored a checkpoint above its storage bound")
		}
	})
	t.Run("variable evidence budget", func(t *testing.T) {
		var h History
		state := historyCheckpoint{Version: 1, Unresolved: []string{}}
		fit := allowlist.MaxSandboxVariableEvidenceBytes / observeAtLimits(t, "x").VariableEvidenceBytes()
		for i := range fit + 1 {
			id := fmt.Sprint(i)
			argv := []string{"run", id}
			h.Record(id, "sha256:a", "", argv, observeAtLimits(t, id))
			state.Sequence++
			state.Records = append(state.Records, checkpointRecord{
				Container: checkpointContainer{Env: observeAtLimits(t, id), Digest: "sha256:a", Argv: argv}, Sequence: state.Sequence, Running: []string{id},
			})
		}
		// Record admits evidence past the budget; only a Bound history is
		// checkpointed, so the unbounded one is refused before it is retained.
		if raw, err := h.Checkpoint(); err == nil || raw != nil || !strings.Contains(err.Error(), "evidence budget") {
			t.Fatalf("unbounded evidence produced usable state or the wrong refusal: %v", err)
		}
		// Syntactically valid stored records above the budget must also be
		// refused on restore, before they can become retained authority.
		raw, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreCheckpoint(raw); err == nil || !strings.Contains(err.Error(), "evidence budget") {
			t.Fatalf("restored evidence without its cumulative budget refusal: %v", err)
		}
		h.Bound(nil)
		_ = restoreHistory(t, h)
	})
}
