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
	podSide = "sha256:" + strings.Repeat("3", 64)
)

func podEntry(t *testing.T, grant *pkgallowlist.SecretsPolicy, digests ...string) pkgallowlist.Workload {
	t.Helper()
	w := pkgallowlist.Workload{Secrets: grant}
	for _, d := range digests {
		parsed, err := types.ParseDigest(d)
		if err != nil {
			t.Fatal(err)
		}
		w.Containers = append(w.Containers, pkgallowlist.Container{
			Digest:  parsed,
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/serve"}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		})
	}
	return w
}

func podClaims(containers ...workloadclaims.PodContainer) workloadclaims.PodClaims {
	c := workloadclaims.PodClaims{Containers: containers}
	for _, x := range containers {
		c.RuntimeExtensions = append(c.RuntimeExtensions, x.Digest)
	}
	return c
}

func userGrant(user string) *pkgallowlist.SecretsPolicy {
	return &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/users/" + user + "/**"}, Write: []string{"/users/" + user + "/**"}}
}

func TestMatchPodGrantIgnoresPlatformContainers(t *testing.T) {
	al := &pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{
		"agent":   podEntry(t, userGrant("a"), podApp, podSide),
		"partial": podEntry(t, userGrant("b"), podApp),
		"nogrant": podEntry(t, nil, podApp, podSide),
	}}
	claims := podClaims(workloadclaims.PodContainer{Digest: podMesh, Role: workloadclaims.MeshRole},
		workloadclaims.PodContainer{Digest: podApp}, workloadclaims.PodContainer{Digest: podSide})
	g, err := MatchPodGrant(al, claims)
	if err != nil || g.Workload != "agent" {
		t.Fatalf("grant=%+v err=%v", g, err)
	}
	if len(g.Readers) != 2 || g.Readers[0] != podApp || g.Readers[1] != podSide {
		t.Fatalf("readers=%v", g.Readers)
	}
}

func TestMatchPodGrantRefuses(t *testing.T) {
	unpinned := podEntry(t, userGrant("a"), podApp)
	unpinned.Containers[0].Command = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
	for name, tc := range map[string]struct {
		al     map[string]pkgallowlist.Workload
		claims workloadclaims.PodClaims
	}{
		"subset of the pod": {map[string]pkgallowlist.Workload{"a": podEntry(t, userGrant("a"), podApp)},
			podClaims(workloadclaims.PodContainer{Digest: podApp}, workloadclaims.PodContainer{Digest: podSide})},
		"superset of the pod": {map[string]pkgallowlist.Workload{"a": podEntry(t, userGrant("a"), podApp, podSide)},
			podClaims(workloadclaims.PodContainer{Digest: podApp})},
		"only platform": {map[string]pkgallowlist.Workload{"a": podEntry(t, userGrant("a"), podMesh)},
			podClaims(workloadclaims.PodContainer{Digest: podMesh, Role: workloadclaims.MeshRole})},
		"unpinned launch": {map[string]pkgallowlist.Workload{"a": unpinned},
			podClaims(workloadclaims.PodContainer{Digest: podApp})},
		// Two users' entries run the same images: digest-only claims cannot
		// tell their pods apart, so neither is released.
		"ambiguous users": {map[string]pkgallowlist.Workload{"user-a": podEntry(t, userGrant("a"), podApp), "user-b": podEntry(t, userGrant("b"), podApp)},
			podClaims(workloadclaims.PodContainer{Digest: podApp})},
	} {
		t.Run(name, func(t *testing.T) {
			if g, err := MatchPodGrant(&pkgallowlist.Allowlist{Workloads: tc.al}, tc.claims); err == nil {
				t.Fatalf("matched %q", g.Workload)
			}
		})
	}
}

// The hook narrows a match to the assigned entry, which is what separates
// two users' pods running the same images.
func TestMatchPodGrantAssignedWorkloadHook(t *testing.T) {
	defer func(f func(workloadclaims.PodClaims) string) { podAssignedWorkload = f }(podAssignedWorkload)
	podAssignedWorkload = func(workloadclaims.PodClaims) string { return "user-b" }
	al := &pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{
		"user-a": podEntry(t, userGrant("a"), podApp), "user-b": podEntry(t, userGrant("b"), podApp)}}
	g, err := MatchPodGrant(al, podClaims(workloadclaims.PodContainer{Digest: podApp}))
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
