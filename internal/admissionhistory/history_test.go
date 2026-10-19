package admissionhistory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestHistoryRetainsDistinctAdmissions(t *testing.T) {
	var h History
	digests, containers, err := h.Snapshot(nil)
	if err != nil || digests == nil || containers == nil || len(digests)+len(containers) != 0 {
		t.Fatalf("empty history = %v, %v, %v", digests, containers, err)
	}
	h.Record("one", "sha256:b", []string{"run", "z"}, nil)
	h.Record("two", "sha256:a", nil, nil)
	h.Record("three", "sha256:a", []string{}, nil)
	h.Record("replica", "sha256:b", []string{"run", "z"}, nil)
	h.Record("one", "sha256:b", []string{"run", "a"}, nil)
	h.Record("one", "sha256:a", []string{""}, nil)
	digests, containers, err = h.Snapshot(nil)
	want := []workloadclaims.SandboxContainer{
		{Digest: "sha256:a", Argv: []string{}},
		{Digest: "sha256:a", Argv: []string{""}},
		{Digest: "sha256:b", Argv: []string{"run", "a"}},
		{Digest: "sha256:b", Argv: []string{"run", "z"}},
	}
	if err != nil || !reflect.DeepEqual(digests, []string{"sha256:a", "sha256:b"}) || !reflect.DeepEqual(containers, want) {
		t.Fatalf("snapshot = %v, %#v, %v", digests, containers, err)
	}
}

func TestHistoryResolutionIsPerContainer(t *testing.T) {
	var h History
	h.Record("known", "sha256:a", nil, nil)
	h.Record("first", "", nil, nil)
	h.Record("second", "", nil, nil)
	assertUnresolved := func() {
		t.Helper()
		digests, containers, err := h.Snapshot(nil)
		if err == nil || digests != nil || containers != nil {
			t.Fatalf("unresolved history returned a partial answer: %v, %v, %v", digests, containers, err)
		}
	}
	assertUnresolved()
	h.Record("different", "sha256:b", nil, nil)
	assertUnresolved()
	h.Record("first", "sha256:b", nil, nil)
	assertUnresolved()
	h.Record("second", "sha256:b", nil, nil)
	if digests, containers, err := h.Snapshot(nil); err != nil || len(digests) != 2 || len(containers) != 2 {
		t.Fatalf("resolved snapshot = %v, %v, %v", digests, containers, err)
	}
	h.Record("known", "", nil, nil)
	assertUnresolved()
	h.Record("known", "sha256:c", nil, nil)
	if digests, _, err := h.Snapshot(nil); err != nil || len(digests) != 3 {
		t.Fatalf("resolution lost an earlier admission: %v, %v", digests, err)
	}
}

func TestHistoryOwnsArgumentsAndSnapshots(t *testing.T) {
	var h History
	argv := []string{"run", "original"}
	h.Record("one", "sha256:a", argv, nil)
	argv[1] = "changed input"
	digests, containers, err := h.Snapshot(nil)
	if err != nil || len(containers) != 1 || containers[0].Argv[1] != "original" {
		t.Fatalf("input mutation changed history: %v, %v", containers, err)
	}
	digests[0] = "changed digest"
	containers[0].Digest = "changed container"
	containers[0].Argv[1] = "changed output"
	digests, containers, err = h.Snapshot(nil)
	if err != nil || !reflect.DeepEqual(digests, []string{"sha256:a"}) || len(containers) != 1 || containers[0].Digest != "sha256:a" || containers[0].Argv[1] != "original" {
		t.Fatalf("snapshot mutation changed history: %v, %v, %v", digests, containers, err)
	}
}

func TestHistoryEnvVariantsAndOwnership(t *testing.T) {
	var h History
	a, _ := allowlist.ObserveEnv([]string{"MODE=a"})
	b, _ := allowlist.ObserveEnv([]string{"MODE=b"})
	h.Record("c", "sha256:a", []string{"run"}, nil) // older/unavailable evidence
	h.Record("c", "sha256:a", []string{"run"}, a)
	h.Record("c", "sha256:a", []string{"run"}, b)
	a.Digest = "mutated"
	a.VariableDigests["MODE"] = "mutated"
	_, cs, err := h.Snapshot(nil)
	if err != nil || len(cs) != 3 {
		t.Fatalf("history lost variants: %v %v", cs, err)
	}
	for _, c := range cs {
		if c.Env != nil {
			if !c.Env.Valid() {
				t.Fatal("history borrowed input")
			}
			c.Env.Digest = "mutated"
			c.Env.VariableDigests["MODE"] = "mutated"
		}
	}
	_, cs, _ = h.Snapshot(nil)
	for _, c := range cs {
		if c.Env != nil && !c.Env.Valid() {
			t.Fatal("snapshot borrowed history")
		}
	}
	// Framing must distinguish an extra argv item from any env field.
	seen := map[string]bool{}
	for _, c := range []workloadclaims.SandboxContainer{
		{Digest: "d", Argv: []string{"run"}, Env: b},
		{Digest: "d", Argv: []string{"run", b.Format, b.Digest}},
		{Digest: "d", Argv: []string{"run"}},
	} {
		if seen[c.Key()] {
			t.Fatal("tuple key collision")
		}
		seen[c.Key()] = true
	}
}

func TestHistoryMountEvidenceAndOwnership(t *testing.T) {
	var h History
	mounts := []allowlist.ObservedMount{{Destination: "/config", Class: allowlist.MountData, Storage: allowlist.MountMemory}}
	h.Record("c", "sha256:a", []string{"run"}, nil, mounts...)
	h.Record("legacy", "sha256:a", []string{"run"}, nil)
	mounts[0].Destination = "/changed"
	_, cs, err := h.Snapshot(nil)
	if err != nil || len(cs) != 2 {
		t.Fatalf("history lost observed and legacy variants: %v %v", cs, err)
	}
	for _, c := range cs {
		if c.Mounts != nil {
			if len(c.Mounts) != 1 || c.Mounts[0].Destination != "/config" {
				t.Fatalf("history borrowed mount observation: %+v", c)
			}
			c.Mounts[0].Destination = "/mutated"
		}
	}
	_, again, _ := h.Snapshot(nil)
	for _, c := range again {
		if c.Mounts != nil && c.Mounts[0].Destination != "/config" {
			t.Fatal("snapshot borrowed history's mount slice")
		}
	}
}

func TestHistoryRetainsDistinctProvenance(t *testing.T) {
	var h History
	for _, evidence := range []struct{ provenance, digest string }{
		{"", ""},
		{allowlist.ProvenanceNodeRoot, ""},
		{allowlist.ProvenanceFSVerity, strings.Repeat("a", 64)},
		{allowlist.ProvenanceFSVerity, strings.Repeat("b", 64)},
	} {
		h.Record("same-id", "sha256:a", nil, nil, allowlist.ObservedMount{Destination: "/usr/bin/nvidia-smi", Class: allowlist.MountHost, ReadOnly: true, Provenance: evidence.provenance, VerityDigest: evidence.digest})
	}
	_, containers, err := h.Snapshot(nil)
	if err != nil || len(containers) != 4 {
		t.Fatalf("lost distinct provenance admissions: %v, %v", containers, err)
	}
}

// observeAtLimits returns an environment at the per-record evidence limits:
// 128 variables and 4 KiB of names.
func observeAtLimits(t *testing.T, value string) *allowlist.EnvObservation {
	t.Helper()
	env := make([]string, 128)
	for i := range env {
		env[i] = fmt.Sprintf("%s%03d=%s", strings.Repeat("V", 29), i, value)
	}
	observation, err := allowlist.ObserveEnv(env)
	if err != nil || observation.VariableDigests == nil {
		t.Fatalf("ObserveEnv() = %v, %v; want per-variable evidence", observation, err)
	}
	return observation
}

func evidenceByEnv(t *testing.T, h History, needed func(string) bool) map[string]*allowlist.EnvObservation {
	t.Helper()
	_, cs, err := h.Snapshot(needed)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*allowlist.EnvObservation{}
	for _, c := range cs {
		if !c.Env.Valid() {
			t.Fatalf("record lost its aggregate digest: %+v", c.Env)
		}
		out[c.Env.Digest] = c.Env
	}
	return out
}

// A live container keeps its evidence while exited variants churn past the
// budget; the oldest exited variants lose theirs first.
func TestHistoryEvictsExitedEvidenceFirst(t *testing.T) {
	var h History
	live := observeAtLimits(t, "live")
	h.Record("main", "sha256:a", []string{"/app"}, live)
	h.Bound(nil)
	perRecord := live.VariableEvidenceBytes()
	fit := allowlist.MaxSandboxVariableEvidenceBytes / perRecord
	var churn []*allowlist.EnvObservation
	for i := range fit + 5 {
		env := observeAtLimits(t, fmt.Sprint(i))
		churn = append(churn, env)
		id := fmt.Sprint("sidecar-", i)
		h.Record(id, "sha256:b", []string{"/sidecar"}, env)
		h.Bound(nil)
		h.Exited(id)
	}
	got := evidenceByEnv(t, h, nil)
	if got[live.Digest].VariableDigests == nil {
		t.Fatal("the running container lost its per-variable evidence to exited variants")
	}
	// The live record holds one slot, so the oldest exited variants past
	// fit-1 lose their evidence.
	evicted := len(churn) - (fit - 1)
	total := perRecord
	for i, env := range churn {
		e := got[env.Digest]
		total += e.VariableEvidenceBytes()
		if wantEvicted := i < evicted; (e.VariableDigests == nil) != wantEvicted || e.VariableDigestsEvicted != wantEvicted {
			t.Errorf("variant %d: evidence dropped %t, marked evicted %t; want %t", i, e.VariableDigests == nil, e.VariableDigestsEvicted, wantEvicted)
		}
	}
	if total > allowlist.MaxSandboxVariableEvidenceBytes {
		t.Fatalf("kept %d bytes of evidence, want at most %d", total, allowlist.MaxSandboxVariableEvidenceBytes)
	}
}

// Past the budget with every container running, an image no match policy lists
// loses its evidence before the oldest image one does.
func TestHistoryEvictsUnneededBeforeOldest(t *testing.T) {
	var h History
	needed := func(digest string) bool { return digest == "sha256:a" }
	fit := allowlist.MaxSandboxVariableEvidenceBytes / observeAtLimits(t, "x").VariableEvidenceBytes()
	first := observeAtLimits(t, "first")
	h.Record("first", "sha256:a", []string{"/app"}, first)
	h.Bound(needed)
	for i := range fit {
		h.Record(fmt.Sprint("other-", i), "sha256:b", []string{"/other"}, observeAtLimits(t, fmt.Sprint(i)))
		h.Bound(needed)
	}
	if got := evidenceByEnv(t, h, nil)[first.Digest]; got.VariableDigests == nil {
		t.Fatal("evicted a needed record while an unneeded one kept its evidence")
	}
}

// An exited init container of a needed image keeps its evidence while running
// containers of an unneeded image lose theirs.
func TestHistoryEvictsUnneededBeforeExited(t *testing.T) {
	var h History
	needed := func(digest string) bool { return digest == "sha256:a" }
	fit := allowlist.MaxSandboxVariableEvidenceBytes / observeAtLimits(t, "x").VariableEvidenceBytes()
	initEnv := observeAtLimits(t, "init")
	h.Record("init", "sha256:a", []string{"/init"}, initEnv)
	h.Bound(needed)
	h.Exited("init")
	for i := range fit {
		h.Record(fmt.Sprint("main-", i), "sha256:b", []string{"/main"}, observeAtLimits(t, fmt.Sprint(i)))
		h.Bound(needed)
	}
	if got := evidenceByEnv(t, h, needed)[initEnv.Digest]; got.VariableDigests == nil {
		t.Fatal("evicted an exited needed record while running unneeded ones kept their evidence")
	}
}

// Before a node applies its policy no image counts as needed, and a running
// container still keeps its evidence while exited variants churn past the
// budget.
func TestHistoryEvictsExitedEvidenceFirstWhenNoneNeeded(t *testing.T) {
	var h History
	none := func(string) bool { return false }
	live := observeAtLimits(t, "live")
	h.Record("main", "sha256:a", []string{"/app"}, live)
	h.Bound(none)
	for i := range allowlist.MaxSandboxVariableEvidenceBytes/live.VariableEvidenceBytes() + 2 {
		id := fmt.Sprint("sidecar-", i)
		h.Record(id, "sha256:b", []string{"/sidecar"}, observeAtLimits(t, fmt.Sprint(i)))
		h.Exited(id)
		h.Bound(none)
	}
	if got := evidenceByEnv(t, h, nil)[live.Digest]; got.VariableDigests == nil {
		t.Fatal("the running container lost its per-variable evidence to exited variants")
	}
}

// Serving decides which records need evidence, so an image listed by a match
// policy only after its container was recorded is still served its evidence.
func TestHistoryServesEvidenceByCurrentPolicy(t *testing.T) {
	var h History
	env := observeAtLimits(t, "x")
	h.Record("c", "sha256:a", []string{"/app"}, env)
	h.Bound(func(string) bool { return false })
	if got := evidenceByEnv(t, h, func(string) bool { return false })[env.Digest]; got.VariableDigests != nil || got.VariableDigestsEvicted {
		t.Fatalf("unneeded record served %+v, want the aggregate digest alone", got)
	}
	if got := evidenceByEnv(t, h, func(string) bool { return true })[env.Digest]; got.VariableDigests == nil {
		t.Fatal("record lost its evidence before a match policy listed its image")
	}
}

// The aggregate digest fixes the per-variable digests, so admitting the same
// environment again restores evicted evidence.
func TestHistoryRestoresEvictedEvidence(t *testing.T) {
	var h History
	env := observeAtLimits(t, "first")
	fit := allowlist.MaxSandboxVariableEvidenceBytes / env.VariableEvidenceBytes()
	h.Record("first", "sha256:a", []string{"/app"}, env)
	h.Exited("first")
	for i := range fit {
		h.Record(fmt.Sprint(i), "sha256:a", []string{"/app"}, observeAtLimits(t, fmt.Sprint(i)))
		h.Bound(nil)
	}
	if evidenceByEnv(t, h, nil)[env.Digest].VariableDigests != nil {
		t.Fatal("setup: the exited record kept its evidence")
	}
	h.Record("again", "sha256:a", []string{"/app"}, env)
	got := evidenceByEnv(t, h, nil)
	if len(got) != fit+1 || got[env.Digest].VariableDigests == nil || got[env.Digest].VariableDigestsEvicted {
		t.Fatalf("re-admission served %+v across %d records, want restored evidence across %d", got[env.Digest], len(got), fit+1)
	}
}

// Every variant sits at the per-record evidence limits; CDS reads at most 1 MiB.
func TestHistoryInventoryFitsResponseLimit(t *testing.T) {
	var h History
	for image := range 4 {
		for variant := range 32 {
			id := fmt.Sprint(image, "-", variant)
			h.Record(id, fmt.Sprintf("sha256:%064d", image), []string{"/app"}, observeAtLimits(t, fmt.Sprint(variant)))
			h.Bound(nil)
		}
	}
	digests, cs, err := h.Snapshot(nil)
	if err != nil || len(cs) != 128 {
		t.Fatalf("Snapshot() = %d records, %v; want 128", len(cs), err)
	}
	body, err := json.Marshal(workloadclaims.SandboxDigestsResponse{Digests: digests, Containers: cs})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) >= 1<<20 {
		t.Fatalf("inventory response = %d bytes, want under 1 MiB", len(body))
	}
}
