//go:build linux

package nriimagepolicy

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// --- F4: a mesh endpoint that STARTS in the deferral window is recovered as
// not-started, refusing the pod for its life ---------------------------------
//
// A pre-existing mesh pod's endpoint is CREATED at the registration-time
// Synchronize snapshot and STARTED during the deferral window. StartContainer's
// not-ready path calls noteMeshStarted -> g.update, a silent no-op while the
// pod is off the gate's record, so meshStarted is never set. Recovery reads the
// container's liveness; before the fix it trusted the stale snapshot
// (CONTAINER_CREATED) and left meshStarted=false, so verifyMember refused the
// pod ("runs no verified mesh endpoint") for its life although its endpoint is
// alive. The fix reads liveness from the running set, which the window's
// StartContainer populated.
//
// Linux-only: recovery proves the pod's network namespace and reads its live
// ruleset (installPodRuleset/nft, CAP_NET_ADMIN). Runs under the nftables suite
// in CI; skipped where that is unavailable.
func TestMeshEndpointStartedInTheDeferralWindowRecoversAsAMember(t *testing.T) {
	requireNetNS(t)

	// The pre-restart enforcer protected the pod, installing its ruleset in the
	// sandbox's own namespace. That ruleset survives the restart.
	pod := sandboxPod(t, "default", "pod")
	before := newMeshGate(*meshRoles(), discardLogger())
	if err := before.protect(pod); err != nil {
		t.Fatalf("protect: %v", err)
	}

	// The restarted plugin shares the mesh policy. Its gate has an empty record.
	cfg := &config{Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: true}, Mesh: meshRoles()}
	p, _ := newCachedPlugin(cfg, exitsAllowlist(t, ""))
	p.mesh = newMeshGate(*cfg.Mesh, discardLogger())
	p.inventory = newAdmissionInventory(t.TempDir())

	// The mesh endpoint: UID marks its role so roleOf returns meshRole. It is
	// CONTAINER_CREATED in the registration snapshot.
	mesh := gateCtr("c8s-mesh", testMeshUID)
	mesh.Id = "c8s-mesh-id"
	mesh.PodSandboxId = pod.GetId()
	mesh.State = api.ContainerState_CONTAINER_CREATED

	// Not ready: Synchronize defers the batch, carrying the mesh ctr as CREATED.
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{mesh}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	// The endpoint starts inside the window. noteMeshStarted is dropped (the pod
	// is off the gate's record), but StartContainer records it on the running
	// set, which is the liveness recovery reads.
	p.running.add(pod, mesh)

	// Recovery runs from the deferred batch.
	p.SetReady()
	p.RunDeferredCheck(context.Background())

	if err := p.mesh.verifyMember(pod.GetId()); err != nil {
		t.Fatalf("a recovered pod whose endpoint started in the deferral window was refused: %v", err)
	}
}
