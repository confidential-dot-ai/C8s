package workloadclaims_test

import (
	"testing"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/types"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

const (
	setCredentialsImg = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	setMeshImg        = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	setWorkloadImg    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	setForeignImg     = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

// setDeadline is when the retiring fixture set below ends.
var setDeadline = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// pinnedEntry is a set entry admitting digest under the launch it pins: the
// executable, any flags, and no mount of the pod's own.
func pinnedEntry(t *testing.T, digest, role, argv0 string) allowlist.Workload {
	t.Helper()
	return allowlist.Workload{Containers: []allowlist.Container{{
		Digest:  mustDigest(t, digest),
		Role:    role,
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{argv0}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyExact},
	}}}
}

func reportedSidecar(digest, role, argv0 string) workloadclaims.SandboxContainer {
	return workloadclaims.SandboxContainer{
		Digest: digest,
		Role:   role,
		Argv:   []string{argv0, "--flag"},
		Mounts: []allowlist.ObservedMount{},
	}
}

// componentDoc is a document whose retiring set declares both sidecars and
// whose current set declares the mesh endpoint alone.
func componentDoc(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	return &allowlist.Allowlist{
		Schema: allowlist.Schema,
		Workloads: map[string]allowlist.Workload{
			"api": {Containers: []allowlist.Container{{
				Digest:  mustDigest(t, setWorkloadImg),
				Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
				Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			}}},
		},
		Components: map[string]allowlist.ComponentSet{
			"0.43.0": {
				Retire: &allowlist.Retirement{Deadline: allowlist.Deadline{Time: setDeadline}},
				Entries: map[string]allowlist.Workload{
					"c8s-credentials": pinnedEntry(t, setCredentialsImg, allowlist.RoleCredentials, "/c8s"),
					"c8s-mesh":        pinnedEntry(t, setMeshImg, allowlist.RoleMesh, "/mesh"),
				},
			},
			"0.44.0": {Entries: map[string]allowlist.Workload{
				"c8s-mesh": pinnedEntry(t, setMeshImg, allowlist.RoleMesh, "/mesh"),
			}},
		},
	}
}

// A pod is on the sets admitting every one of its component containers, and on
// no set at all once none of them admits one.
func TestComponentSets(t *testing.T) {
	al := componentDoc(t)
	workload := workloadclaims.SandboxContainer{Digest: setWorkloadImg, Argv: []string{"/serve"}}
	credentials := reportedSidecar(setCredentialsImg, allowlist.RoleCredentials, "/c8s")
	mesh := reportedSidecar(setMeshImg, allowlist.RoleMesh, "/mesh")
	before := setDeadline.Add(-time.Hour)

	for _, tc := range []struct {
		name     string
		reported []workloadclaims.SandboxContainer
		now      time.Time
		want     []string
		refused  bool
	}{
		{
			name:     "no component container",
			reported: []workloadclaims.SandboxContainer{workload},
			now:      before,
		},
		{
			name:     "both sidecars on the retiring set",
			reported: []workloadclaims.SandboxContainer{workload, credentials, mesh},
			now:      before,
			want:     []string{"0.43.0"},
		},
		{
			name:     "a sidecar only the current set admits",
			reported: []workloadclaims.SandboxContainer{workload, mesh},
			now:      before,
			want:     []string{"0.43.0", "0.44.0"},
		},
		{
			name:     "a sidecar on a set beside one no set admits",
			reported: []workloadclaims.SandboxContainer{workload, credentials, mesh},
			now:      setDeadline,
			refused:  true,
		},
		{
			name:     "no set admits either sidecar",
			reported: []workloadclaims.SandboxContainer{workload, reportedSidecar(setForeignImg, allowlist.RoleMesh, "/other")},
			now:      before,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets, err := workloadclaims.ComponentSets(al, tc.reported, tc.now)
			if tc.refused {
				if err == nil {
					t.Fatalf("sets = %v, want a refusal", sets)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			versions := make([]string, 0, len(sets))
			for _, ref := range sets {
				versions = append(versions, ref.Version)
			}
			if len(versions) != len(tc.want) {
				t.Fatalf("sets = %v, want %v", versions, tc.want)
			}
			for i, want := range tc.want {
				if versions[i] != want {
					t.Fatalf("sets = %v, want %v", versions, tc.want)
				}
			}
		})
	}
}

// The membership gate covers the entries of the sets in force, and the deadline
// alone ends that admission.
func TestRequireAllowlisted(t *testing.T) {
	al := componentDoc(t)
	reported := []workloadclaims.SandboxContainer{
		{Digest: setWorkloadImg, Argv: []string{"/serve"}},
		reportedSidecar(setCredentialsImg, allowlist.RoleCredentials, "/c8s"),
	}
	if err := workloadclaims.RequireAllowlisted(al, reported, setDeadline.Add(-time.Hour)); err != nil {
		t.Fatalf("before the deadline: %v", err)
	}
	if err := workloadclaims.RequireAllowlisted(al, reported, setDeadline); err == nil {
		t.Fatal("the retiring set's image is still allowlisted at its deadline")
	}
	foreign := []workloadclaims.SandboxContainer{{Digest: setForeignImg}}
	if err := workloadclaims.RequireAllowlisted(al, foreign, setDeadline.Add(-time.Hour)); err == nil {
		t.Fatal("an image no entry lists passed the membership gate")
	}
}
