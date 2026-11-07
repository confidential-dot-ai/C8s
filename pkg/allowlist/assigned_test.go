package allowlist

import (
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestAssignedOnlyEntriesMatchByNameOnly(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	digest, err := types.ParseDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	entry := Workload{AssignedOnly: true, Containers: []Container{{Digest: digest,
		Command: ArgvPolicy{Policy: PolicyExact, Argv: []string{"/opencode"}}, Args: ArgvPolicy{Policy: PolicyDeny}}}}
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"alice": entry, "bob": entry}}
	running := []RunningContainer{{Digest: d, Argv: []string{"/opencode"}, Mounts: []ObservedMount{}}}
	if _, _, err := al.MatchWorkload(running); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("observation match reached an assigned-only entry: %v", err)
	}
	if _, err := al.MatchAssigned("bob", running); err != nil {
		t.Fatalf("assigned match: %v", err)
	}
	if _, err := al.MatchAssigned("carol", running); err == nil {
		t.Fatal("matched an entry that does not exist")
	}
	if _, err := al.MatchAssigned("bob", []RunningContainer{{Digest: d, Argv: []string{"/other"}, Mounts: []ObservedMount{}}}); err == nil {
		t.Fatal("assigned entry matched a different launch")
	}
	// The mark survives the canonical document.
	b, err := al.Canonical()
	if err != nil || !strings.Contains(string(b), `"assignedOnly":true`) {
		t.Fatalf("%s %v", b, err)
	}
	back, err := ParseJSON(b)
	if err != nil || !back.Workloads["alice"].AssignedOnly {
		t.Fatalf("round trip: %v", err)
	}
}
