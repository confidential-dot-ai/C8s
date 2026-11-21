package nriimagepolicy

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestMeshPeerRequirementCannotBeRemovedOrReplaced(t *testing.T) {
	state := &protectedPod{}
	mesh := gatedContainer{role: meshRole, digest: "digest", argv: []string{"mesh"}, peerWorkloads: "worker"}
	state.recordLaunch(mesh)
	for _, value := range []string{"", "other", "worker,other"} {
		replacement := mesh
		replacement.peerWorkloads = value
		if state.admittedBefore(replacement) {
			t.Errorf("weaker replacement %q was treated as the same launch", value)
		}
		if err := state.requirePeerWorkloads(replacement); err == nil {
			t.Errorf("mesh policy changed to %q without rejection", value)
		}
	}
	for _, tc := range []struct {
		value   string
		allowed bool
	}{
		{value: "worker", allowed: true},
		{value: "other"},
	} {
		err := state.requirePeerWorkloads(gatedContainer{peerWorkloads: tc.value})
		if (err == nil) != tc.allowed {
			t.Errorf("application policy %q: %v", tc.value, err)
		}
	}
	if err := (&protectedPod{}).requirePeerWorkloads(gatedContainer{peerWorkloads: "worker"}); err == nil {
		t.Fatal("application admitted before its required endpoint")
	}
}

func TestFinalMeshEnvironmentCannotDowngradeValidatedRequirement(t *testing.T) {
	pod := meshPod("default", "pod", testNetNS)
	gate, state := gateWithPod(pod)
	state.recordLaunch(gatedContainer{role: meshRole, peerWorkloads: "worker"})
	p := newTestPlugin(&config{Allowlist: allowlistConfig{Base: roleBase(t, pushDigestA, meshRole, []string{"mesh"})}})
	p.mesh = gate
	endpoint := makeCtrWithImageArgs(pod.GetId(), "mesh", "registry/repo@"+pushDigestA, []string{"mesh"})
	for _, env := range [][]string{nil, {workloadclaims.MeshPeerWorkloadsEnv + "="}, {workloadclaims.MeshPeerWorkloadsEnv + "=other"}} {
		endpoint.Env = env
		if _, err := p.cvm().gateStart(t.Context(), pod, endpoint, "registry/repo@"+pushDigestA); err == nil {
			t.Fatalf("post-validation environment %v downgraded the endpoint", env)
		}
	}
	endpoint.Env = []string{workloadclaims.MeshPeerWorkloadsEnv + "=worker"}
	if _, err := p.cvm().gateStart(t.Context(), pod, endpoint, "registry/repo@"+pushDigestA); err != nil {
		t.Fatal(err)
	}
}
