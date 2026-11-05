package secrets

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/admissionhistory"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestProcessNamespaceEvidenceSurvivesInventoryAndMatching(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	entry, err := allowlist.ParseWorkloadJSON([]byte(`{"containers":[{"digest":"` + digest + `","command":{"policy":"exact","argv":["/worker"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"shareProcessNamespace":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	env, err := allowlist.ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	launch := allowlist.RunningContainer{
		Digest:                 digest,
		Argv:                   []string{"/worker"},
		Env:                    env,
		Mounts:                 []allowlist.ObservedMount{},
		ProcessNamespacePolicy: entry.ProcessNamespacePolicy(),
	}
	var history admissionhistory.History
	history.RecordLaunch("shared", "", launch)
	digests, containers, err := history.Snapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(workloadclaims.SandboxDigestsResponse{Digests: digests, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	var decoded workloadclaims.SandboxDigestsResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Containers) != 1 || decoded.Containers[0].ProcessNamespacePolicy != launch.ProcessNamespacePolicy {
		t.Fatalf("wire report lost namespace evidence: %s", encoded)
	}
	observed := WorkloadContainers(decoded.Containers)
	if diff := entry.Diff(observed); !diff.Describes() {
		t.Fatalf("complete evidence did not match: %+v", diff)
	}
	for _, policy := range []string{"", "sha256:" + strings.Repeat("b", 64)} {
		decoded.Containers[0].ProcessNamespacePolicy = policy
		if entry.Diff(WorkloadContainers(decoded.Containers)).Describes() {
			t.Fatalf("matched with missing or different policy %q", policy)
		}
		launch.ProcessNamespacePolicy = policy
		history.RecordLaunch("changed", "", launch)
	}
	_, containers, err = history.Snapshot(nil)
	if err != nil || len(containers) != 3 {
		t.Fatalf("history collapsed different namespace admissions: %d, %v", len(containers), err)
	}
	if entry.Diff(WorkloadContainers(containers)).Describes() {
		t.Fatal("historical namespace mismatch did not block workload matching")
	}
}
