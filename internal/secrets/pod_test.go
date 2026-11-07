package secrets

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var (
	podApp  = "sha256:" + strings.Repeat("1", 64)
	podMesh = "sha256:" + strings.Repeat("2", 64)
)

func podEntry(t *testing.T, grant *pkgallowlist.SecretsPolicy, digest string, argv ...string) pkgallowlist.Workload {
	t.Helper()
	parsed, err := types.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Secrets: grant, Containers: []pkgallowlist.Container{{
		Digest:  parsed,
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: argv},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
	}}}
}

func podObserved(t *testing.T, digest, role string, argv ...string) workloadclaims.SandboxContainer {
	t.Helper()
	env, err := pkgallowlist.ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	return workloadclaims.SandboxContainer{Digest: digest, Role: role, Argv: argv, Env: env, Mounts: []pkgallowlist.ObservedMount{}}
}

// podClaims is an OpenCode pod: the mesh endpoint and one workload container.
func podClaims(t *testing.T, assigned string, argv ...string) workloadclaims.PodClaims {
	return workloadclaims.PodClaims{AssignedWorkloadID: assigned, RuntimeExtensions: []string{podMesh, podApp}, Containers: []workloadclaims.SandboxContainer{
		podObserved(t, podMesh, workloadclaims.MeshRole, "/endpoint"), podObserved(t, podApp, "", argv...)}}
}

func userGrant(user string) *pkgallowlist.SecretsPolicy {
	return &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/users/" + user + "/**"}, Write: []string{"/users/" + user + "/**"}}
}

// Two users run the same image the same way; only the assigned workload ID
// tells their pods apart, and each gets its own grant.
func sameImageUsers(t *testing.T) *pkgallowlist.Allowlist {
	return &pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{
		"user-a":   podEntry(t, userGrant("a"), podApp, "/opencode"),
		"user-b":   podEntry(t, userGrant("b"), podApp, "/opencode"),
		"no-grant": podEntry(t, nil, podApp, "/opencode"),
	}}
}

func TestMatchPodGrantByAssignedWorkload(t *testing.T) {
	al := sameImageUsers(t)
	for _, user := range []string{"user-a", "user-b"} {
		g, err := MatchPodGrant(al, podClaims(t, user, "/opencode"))
		if err != nil || g.Workload != user || len(g.Readers) != 1 || g.Readers[0] != podApp {
			t.Fatalf("%s: grant=%+v err=%v", user, g, err)
		}
	}
}

func TestMatchPodGrantRefuses(t *testing.T) {
	for name, claims := range map[string]workloadclaims.PodClaims{
		"same images without an assigned ID": podClaims(t, "", "/opencode"),
		"assigned ID with no entry":          podClaims(t, "user-c", "/opencode"),
		"assigned entry holds no grant":      podClaims(t, "no-grant", "/opencode"),
		"assigned entry, other launch":       podClaims(t, "user-a", "/opencode", "--evil"),
	} {
		t.Run(name, func(t *testing.T) {
			if g, err := MatchPodGrant(sameImageUsers(t), claims); err == nil {
				t.Fatalf("matched %q", g.Workload)
			}
		})
	}
	unpinned := podEntry(t, userGrant("a"), podApp, "/opencode")
	unpinned.Containers[0].Command = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
	if _, err := MatchPodGrant(&pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{"a": unpinned}}, podClaims(t, "a", "/opencode")); err == nil {
		t.Fatal("matched an entry that leaves the launch open")
	}
}

// Without an assigned ID, entries whose launches differ are told apart by the
// observed spec, which the claims' spec digests commit to.
// Assigned-only entries share a shape by design; a pod reaches one only
// through its assignment, never by observation.
func TestMatchPodGrantAssignedOnly(t *testing.T) {
	al := &pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{}}
	for _, user := range []string{"alice", "bob"} {
		e := podEntry(t, userGrant(user), podApp, "/opencode")
		e.AssignedOnly = true
		al.Workloads[user] = e
	}
	if g, err := MatchPodGrant(al, podClaims(t, "bob", "/opencode")); err != nil || g.Workload != "bob" {
		t.Fatalf("grant=%q err=%v", g.Workload, err)
	}
	solo := &pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{"alice": al.Workloads["alice"]}}
	if g, err := MatchPodGrant(solo, podClaims(t, "", "/opencode")); err == nil {
		t.Fatalf("a pod without an assignment reached %q", g.Workload)
	}
}

func TestMatchPodGrantBySpecWithoutAssignedWorkload(t *testing.T) {
	al := &pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{
		"user-a": podEntry(t, userGrant("a"), podApp, "/opencode", "--user=a"),
		"user-b": podEntry(t, userGrant("b"), podApp, "/opencode", "--user=b"),
	}}
	g, err := MatchPodGrant(al, podClaims(t, "", "/opencode", "--user=b"))
	if err != nil || g.Workload != "user-b" {
		t.Fatalf("grant=%q err=%v", g.Workload, err)
	}
}

func TestReleasePodSecret(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(16, 8, 64).Local()
	g := PodGrant{Workload: "user-a", Secrets: userGrant("a")}
	created, err := ReleasePodSecret(ctx, store, g, "/users/a/key")
	if err != nil || len(created) != GeneratedValueBytes {
		t.Fatalf("create: %v", err)
	}
	again, err := ReleasePodSecret(ctx, store, g, "/users/a/key")
	if err != nil || !bytes.Equal(again, created) {
		t.Fatalf("re-read: %v", err)
	}
	if _, err := ReleasePodSecret(ctx, store, g, "/users/b/key"); !errors.Is(err, ErrPodSecretUngranted) {
		t.Fatalf("other user's path: %v", err)
	}
	readOnly := PodGrant{Workload: "user-a", Secrets: &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/users/a/**"}}}
	if _, err := ReleasePodSecret(ctx, store, readOnly, "/users/a/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read-only missing: %v", err)
	}
	if v, err := ReleasePodSecret(ctx, store, readOnly, "/users/a/key"); err != nil || !bytes.Equal(v, created) {
		t.Fatalf("read-only existing: %v", err)
	}
}
