package admissionhistory

import (
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestHistoryRetainsDistinctAdmissions(t *testing.T) {
	var h History
	digests, containers, err := h.Snapshot()
	if err != nil || digests == nil || containers == nil || len(digests)+len(containers) != 0 {
		t.Fatalf("empty history = %v, %v, %v", digests, containers, err)
	}
	h.Record("one", "sha256:b", []string{"run", "z"}, nil)
	h.Record("two", "sha256:a", nil, nil)
	h.Record("three", "sha256:a", []string{}, nil)
	h.Record("replica", "sha256:b", []string{"run", "z"}, nil)
	h.Record("one", "sha256:b", []string{"run", "a"}, nil)
	h.Record("one", "sha256:a", []string{""}, nil)
	digests, containers, err = h.Snapshot()
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
		digests, containers, err := h.Snapshot()
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
	if digests, containers, err := h.Snapshot(); err != nil || len(digests) != 2 || len(containers) != 2 {
		t.Fatalf("resolved snapshot = %v, %v, %v", digests, containers, err)
	}
	h.Record("known", "", nil, nil)
	assertUnresolved()
	h.Record("known", "sha256:c", nil, nil)
	if digests, _, err := h.Snapshot(); err != nil || len(digests) != 3 {
		t.Fatalf("resolution lost an earlier admission: %v, %v", digests, err)
	}
}

func TestHistoryOwnsArgumentsAndSnapshots(t *testing.T) {
	var h History
	argv := []string{"run", "original"}
	h.Record("one", "sha256:a", argv, nil)
	argv[1] = "changed input"
	digests, containers, err := h.Snapshot()
	if err != nil || len(containers) != 1 || containers[0].Argv[1] != "original" {
		t.Fatalf("input mutation changed history: %v, %v", containers, err)
	}
	digests[0] = "changed digest"
	containers[0].Digest = "changed container"
	containers[0].Argv[1] = "changed output"
	digests, containers, err = h.Snapshot()
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
	_, cs, err := h.Snapshot()
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
	_, cs, _ = h.Snapshot()
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
	_, cs, err := h.Snapshot()
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
	_, again, _ := h.Snapshot()
	for _, c := range again {
		if c.Mounts != nil && c.Mounts[0].Destination != "/config" {
			t.Fatal("snapshot borrowed history's mount slice")
		}
	}
}
