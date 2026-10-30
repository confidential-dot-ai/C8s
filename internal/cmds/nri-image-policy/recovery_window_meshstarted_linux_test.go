//go:build linux

package nriimagepolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// Recovery must read liveness from the running set when a measured mesh
// endpoint starts after the registration snapshot. The reserved UID alone
// grants no role, and an endpoint that remains CREATED opens no member gate.
// Linux-only: recovery reads the live ruleset in the sandbox's own namespace.
func TestMeshEndpointStartedInTheDeferralWindowRecoversAsAMember(t *testing.T) {
	requireNetNS(t)
	for _, tc := range []struct {
		name      string
		image     string
		argv      []string
		started   bool
		refused   string
		wantStops int
	}{
		{
			name:    "measured endpoint started during deferral",
			image:   "registry/c8s@" + pushDigestB,
			argv:    []string{"/app/c8s", "armtls-mesh"},
			started: true,
		},
		{
			name:    "measured endpoint never started",
			image:   "registry/c8s@" + pushDigestB,
			argv:    []string{"/app/c8s", "armtls-mesh"},
			refused: "runs no verified mesh endpoint",
		},
		{
			name:    "reserved UID alone",
			started: true,
			refused: "reserved for the mesh role",
		},
		{
			name:      "measured image with a different command",
			wantStops: 1,
			image:     "registry/c8s@" + pushDigestB,
			argv:      []string{"/app/c8s", "get-cert"},
			started:   true,
			refused:   "reserved for the mesh role",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The pre-restart enforcer's ruleset survives in the pod's namespace.
			pod := sandboxPod(t, "default", "pod")
			before := newMeshGate(*meshRoles(), discardLogger())
			if err := before.protect(pod); err != nil {
				t.Fatalf("protect: %v", err)
			}

			cfg := &config{
				Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
				Mesh:   meshRoles(),
				Allowlist: allowlistConfig{
					Base: roleBase(t, pushDigestB, meshRole, []string{"/app/c8s", "armtls-mesh"}),
				},
			}
			p, _ := newCachedPlugin(cfg, exitsAllowlist(t, ""))
			p.inventory = newAdmissionInventory(t.TempDir())
			stops := 0
			p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
				if id != "c8s-mesh-id" {
					t.Fatalf("stopped unexpected container %q", id)
				}
				stops++
				return nil
			}}

			// Only the measured base's digest and command establish the role.
			mesh := gateCtr("c8s-mesh", testMeshUID)
			mesh.Id = "c8s-mesh-id"
			mesh.PodSandboxId = pod.GetId()
			mesh.State = api.ContainerState_CONTAINER_CREATED
			mesh.Annotations = map[string]string{annotationImageName: tc.image}
			mesh.Args = tc.argv
			if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{mesh}); err != nil {
				t.Fatalf("Synchronize: %v", err)
			}

			// StartContainer records liveness while the gate has no record yet.
			// Leave the registration snapshot CREATED to exercise that window.
			if tc.started {
				p.running.add(pod, mesh)
			}
			p.SetReady()
			p.RunDeferredCheck(context.Background())
			if stops != tc.wantStops {
				t.Fatalf("stopped %d containers, want %d", stops, tc.wantStops)
			}

			err := p.mesh.verifyMember(pod.GetId())
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("verifyMember = %v, want refusal containing %q", err, tc.refused)
				}
			} else if err != nil {
				t.Fatalf("a recovered pod whose measured endpoint started in the deferral window was refused: %v", err)
			}
		})
	}
}
