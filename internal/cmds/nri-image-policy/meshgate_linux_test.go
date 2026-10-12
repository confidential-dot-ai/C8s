//go:build linux

package nriimagepolicy

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
)

// notANamespace is a regular file: it exists, so the enforcer reads it, and it
// is not a network namespace, so nothing it reads proves one.
func notANamespace(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "not-a-namespace")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The pod ruleset comes from trusted policy alone: the mesh endpoint's
// reserved UID owns the capture ports, and every other role carries only the
// destinations its binding names.
func TestPodRulesetCarriesTrustedPolicyOnly(t *testing.T) {
	policy := meshRoles()
	policy.Roles = append(policy.Roles, roleBinding{
		Name: routerRole,
		UID:  testRouterUID,
		Destinations: []netip.AddrPort{
			netip.MustParseAddrPort("10.43.0.6:8443"),
			netip.MustParseAddrPort("10.43.0.7:9443"),
		},
	})

	want := ruleset.Policy{
		Resolver: netip.MustParseAddr("10.43.0.10"),
		Capture: ruleset.CapturePorts{
			Outbound: 15001,
			Inbound:  15006,
			Health:   15021,
		},
		MeshUID: testMeshUID,
		Roles: []ruleset.Role{
			{
				UID: testCertUID,
				Destinations: []ruleset.Destination{
					{
						Addr: netip.MustParseAddr("10.43.0.5"),
						Port: 8443,
					},
				},
			},
			{
				UID: testRouterUID,
				Destinations: []ruleset.Destination{
					{
						Addr: netip.MustParseAddr("10.43.0.6"),
						Port: 8443,
					},
					{
						Addr: netip.MustParseAddr("10.43.0.7"),
						Port: 9443,
					},
				},
			},
		},
	}
	if got := policy.podRuleset(); !reflect.DeepEqual(got, want) {
		t.Fatalf("podRuleset = %+v, want %+v", got, want)
	}
}

// The path the runtime reports is proven against the sandbox's own process
// before anything is installed into it: a path that is the node's own
// namespace, another file, or has no live process behind it proves nothing.
func TestProveSandboxNamespaceRefusals(t *testing.T) {
	regular := notANamespace(t)
	for _, tc := range []struct {
		name  string
		path  string
		pid   uint32
		wants string
	}{
		{
			name:  "no sandbox process to prove against",
			path:  "/proc/self/ns/net",
			wants: "no sandbox process",
		},
		{
			name:  "a path that names nothing",
			path:  filepath.Join(t.TempDir(), "gone"),
			pid:   uint32(os.Getpid()),
			wants: "describe network namespace",
		},
		{
			name:  "the node's own namespace",
			path:  "/proc/self/ns/net",
			pid:   uint32(os.Getpid()),
			wants: "the node's own network namespace",
		},
		{
			name:  "a sandbox process that is gone",
			path:  regular,
			pid:   1 << 30,
			wants: "describe network namespace",
		},
		{
			name:  "another file than the sandbox's namespace",
			path:  regular,
			pid:   uint32(os.Getpid()),
			wants: "is not the network namespace of sandbox process",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proven, err := proveSandboxNamespace(tc.path, tc.pid)
			if err == nil {
				t.Fatalf("proved %s as the sandbox's namespace", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
			if proven.id != (fileID{}) {
				t.Fatalf("an unproven namespace carries a file identity: %+v", proven)
			}
		})
	}
}

// A namespace that cannot be described, or whose file is another one than the
// enforcer installed into, verifies nothing: the live rules of another
// namespace say nothing about this pod.
func TestVerifyPodRulesetNeedsTheInstalledNamespace(t *testing.T) {
	gone := podNamespace{path: filepath.Join(t.TempDir(), "gone")}
	err := verifyPodRuleset(gone, *meshRoles())
	if err == nil || !strings.Contains(err.Error(), "describe network namespace") {
		t.Fatalf("error = %v, want the unreadable-namespace refusal", err)
	}

	regular := notANamespace(t)
	described, err := namespaceFile(regular)
	if err != nil {
		t.Fatal(err)
	}
	replaced := podNamespace{
		path: regular,
		id: fileID{
			device: described.id.device,
			inode:  described.id.inode + 1,
		},
	}
	err = verifyPodRuleset(replaced, *meshRoles())
	if err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("error = %v, want the replaced-namespace refusal", err)
	}
}

// A sandbox whose namespace the enforcer cannot prove is refused for its life:
// the install never ran, so no later check can establish protection the pod
// never had.
func TestProtectRefusesASandboxItCannotProve(t *testing.T) {
	pod := meshPod("default", "pod", filepath.Join(t.TempDir(), "gone"))
	gate := newMeshGate(meshRoles(), discardLogger())

	err := gate.protect(pod)
	if err == nil || !strings.Contains(err.Error(), "protect pod default/pod") {
		t.Fatalf("error = %v, want the install refusal", err)
	}
	if gate.pods[pod.GetId()].refusal == nil {
		t.Fatal("a sandbox whose install failed carries no refusal")
	}
	workload := &api.Container{
		Name: "app",
		User: &api.User{Uid: testWorkloadUID},
	}
	if err := gate.admit(pod, workload, gatedContainer{}); err == nil {
		t.Fatal("a container of an unprotected sandbox was admitted")
	}
	if err := gate.verifyMember(pod.GetId()); err == nil {
		t.Fatal("an unprotected sandbox was verified as a member")
	}

	// A pod the mesh does not host needs no install, and a second sandbox
	// event leaves the refusal that stands.
	if err := gate.protect(makePod("default", "host-network")); err != nil {
		t.Fatalf("a pod outside the mesh's scope was refused: %v", err)
	}
	if err := gate.protect(pod); err == nil || !strings.Contains(err.Error(), "on record already") {
		t.Fatalf("error = %v, want the on-record refusal", err)
	}
}

// The gate's record is not enough on its own: a container is created, and an
// assertion signed, only once the live ruleset of the pod's namespace is read
// and found to be the one trusted policy defines.
func TestAdmitAndVerifyReadTheLiveRuleset(t *testing.T) {
	regular := notANamespace(t)
	described, err := namespaceFile(regular)
	if err != nil {
		t.Fatal(err)
	}
	pod := meshPod("default", "pod", regular)
	gate := newMeshGate(meshRoles(), discardLogger())
	gate.pods[pod.GetId()] = &protectedPod{netns: described}

	mesh := &api.Container{
		Name: "c8s-mesh",
		User: &api.User{Uid: testMeshUID},
	}
	if _, err := gate.admissible(pod, mesh, gatedContainer{role: meshRole}); err != nil {
		t.Fatalf("the enforcer's own record refused the mesh endpoint: %v", err)
	}
	if err := gate.admit(pod, mesh, gatedContainer{role: meshRole}); err == nil {
		t.Fatal("a container was admitted without a verified ruleset")
	}

	gate.noteMeshStarted(pod.GetId())
	if _, err := gate.memberNamespace(pod.GetId()); err != nil {
		t.Fatalf("the record refused a member namespace: %v", err)
	}
	if err := gate.verifyMemberRuleset(pod.GetId()); err == nil {
		t.Fatal("a sandbox with no verified ruleset was verified as a member")
	}
}

// A sandbox event the enforcer cannot act on still leaves the gate deciding:
// the install failure is reported, not returned, and the pod's record carries
// the refusal its containers then meet.
func TestRunPodSandboxRecordsAnInstallItCouldNotDo(t *testing.T) {
	pod := meshPod("default", "pod", filepath.Join(t.TempDir(), "gone"))
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.mesh = newMeshGate(meshRoles(), discardLogger())

	if err := p.RunPodSandbox(context.Background(), pod); err != nil {
		t.Fatalf("a sandbox event failed on an install the enforcer could not do: %v", err)
	}
	if p.mesh.pods[pod.GetId()].refusal == nil {
		t.Fatal("a sandbox whose install failed carries no refusal")
	}

	if err := p.RemovePodSandbox(context.Background(), pod); err != nil {
		t.Fatalf("removing a sandbox failed: %v", err)
	}
	if _, onRecord := p.mesh.pods[pod.GetId()]; onRecord {
		t.Fatal("a removed sandbox is still on the gate's record")
	}
}
