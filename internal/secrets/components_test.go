package secrets

import (
	"net/http"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

var setDeadline = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

// pinnedEntry is a set entry admitting digest under the launch it pins: the
// executable, any flags, and no mount of the pod's own.
func pinnedEntry(t *testing.T, digest string, role string, argv0 string) pkgallowlist.Workload {
	t.Helper()
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{
		Digest:  mustDigest(t, digest),
		Role:    role,
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{argv0}},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Mounts:  pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyExact},
	}}}
}

// componentSet is a set, retiring at setDeadline when retires is true, whose
// entries admit the given sidecars.
func componentSet(t *testing.T, retires bool, entries map[string]pkgallowlist.Workload) pkgallowlist.ComponentSet {
	t.Helper()
	set := pkgallowlist.ComponentSet{Entries: entries}
	if retires {
		set.Retire = &pkgallowlist.Retirement{Deadline: pkgallowlist.Deadline{Time: setDeadline}}
	}
	return set
}

func reportedSidecar(digest, role, argv0 string) workloadclaims.SandboxContainer {
	return workloadclaims.SandboxContainer{
		Digest: digest,
		Role:   role,
		Argv:   []string{argv0, "--flag"},
		Mounts: []pkgallowlist.ObservedMount{},
	}
}

// A pod is on the sets admitting every one of its component containers, and on
// no set at all once none of them admits one.
func TestComponentSets(t *testing.T) {
	al := &pkgallowlist.Allowlist{
		Schema: pkgallowlist.Schema,
		Components: map[string]pkgallowlist.ComponentSet{
			"0.43.0": componentSet(t, true, map[string]pkgallowlist.Workload{
				"c8s-credentials": pinnedEntry(t, testInjected, roleCredentials, "/c8s"),
				"c8s-mesh":        pinnedEntry(t, testMeshImg, roleMesh, "/mesh"),
			}),
			"0.44.0": componentSet(t, false, map[string]pkgallowlist.Workload{
				"c8s-mesh": pinnedEntry(t, testMeshImg, roleMesh, "/mesh"),
			}),
		},
	}
	workload := workloadclaims.SandboxContainer{Digest: testAppImg, Argv: []string{"/serve"}}
	credentials := reportedSidecar(testInjected, roleCredentials, "/c8s")
	mesh := reportedSidecar(testMeshImg, roleMesh, "/mesh")
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
			reported: []workloadclaims.SandboxContainer{workload, reportedSidecar(testOther, roleMesh, "/other")},
			now:      before,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets, err := ComponentSets(al, tc.reported, tc.now)
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

// Release runs on the same membership issuance does: a pod whose component
// containers come from two sets is on neither, and its secret is refused.
func TestSecretRefusedWhenComponentContainersMixSets(t *testing.T) {
	hn := newHarness(t)
	al, err := hn.h.Policy.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	al.Components = map[string]pkgallowlist.ComponentSet{
		"0.43.0": componentSet(t, false, map[string]pkgallowlist.Workload{
			"c8s-credentials": pinnedEntry(t, testInjected, roleCredentials, "/c8s"),
		}),
		"0.44.0": componentSet(t, false, map[string]pkgallowlist.Workload{
			"c8s-mesh": pinnedEntry(t, testMeshImg, roleMesh, "/mesh"),
		}),
	}
	hn.inv.containers = []workloadclaims.SandboxContainer{
		{Digest: testAppImg, Argv: []string{"/serve"}},
		{Digest: testAppImg2, Argv: []string{"/metrics"}},
		reportedSidecar(testInjected, roleCredentials, "/c8s"),
		reportedSidecar(testMeshImg, roleMesh, "/mesh"),
	}
	value := []byte("tenant-value")
	hn.seed(t, "/api/x", value)

	w := do(hn.h, hn.request(t, http.MethodGet, "/api/x"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, value)

	al.Components["0.43.0"].Entries["c8s-mesh"] = pinnedEntry(t, testMeshImg, roleMesh, "/mesh")
	admitted := hn.requestWith(t, http.MethodGet, "/api/x", hn.leaf, testSandbox, []byte("one-set"))
	if w := do(hn.h, admitted); w.Code != http.StatusOK {
		t.Fatalf("one set admitting both sidecars: status = %d, want 200; body = %s", w.Code, w.Body)
	}
}

// A pod whose component set has ended gets no secret: its sidecars are listed
// by no entry in force, whatever its workload containers match.
func TestSecretRefusedWhenTheComponentSetHasEnded(t *testing.T) {
	hn := newHarness(t)
	al, err := hn.h.Policy.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	al.Components = map[string]pkgallowlist.ComponentSet{
		"0.43.0": componentSet(t, true, map[string]pkgallowlist.Workload{
			"c8s-mesh": pinnedEntry(t, testMeshImg, roleMesh, "/mesh"),
		}),
	}
	hn.inv.containers = []workloadclaims.SandboxContainer{
		{Digest: testAppImg, Argv: []string{"/serve"}},
		{Digest: testAppImg2, Argv: []string{"/metrics"}},
		reportedSidecar(testMeshImg, roleMesh, "/mesh"),
	}
	value := []byte("tenant-value")
	hn.seed(t, "/api/x", value)

	hn.h.Now = func() time.Time { return setDeadline.Add(-time.Hour) }
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/x")); w.Code != http.StatusOK {
		t.Fatalf("before the deadline: status = %d, want 200; body = %s", w.Code, w.Body)
	}

	hn.h.Now = func() time.Time { return setDeadline }
	w := do(hn.h, hn.requestWith(t, http.MethodGet, "/api/x", hn.leaf, testSandbox, []byte("ended")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("at the deadline: status = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, value)
}
