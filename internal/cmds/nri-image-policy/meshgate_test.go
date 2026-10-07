package nriimagepolicy

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// testNetNS is a namespace path the state tests never open: they drive the
// enforcer's own record, which decides before any ruleset is read.
const testNetNS = "/run/netns/cni-test"

// meshPod is a pod with its own network namespace, as containerd reports one.
func meshPod(namespace, name, netnsPath string) *api.PodSandbox {
	pod := makePod(namespace, name)
	pod.Pid = 4242
	pod.Linux = &api.LinuxPodSandbox{Namespaces: []*api.LinuxNamespace{
		{Type: "pid", Path: "/proc/4242/ns/pid"},
		{Type: "network", Path: netnsPath},
	}}
	return pod
}

// gateWithPod returns a gate already holding a protected sandbox, so the
// state rules can be exercised without a kernel namespace.
func gateWithPod(pod *api.PodSandbox) (*meshGate, *protectedPod) {
	gate := newMeshGate(meshRoles(), slog.Default())
	state := &protectedPod{netns: podNamespace{path: testNetNS, id: fileID{device: 3, inode: 7}}}
	gate.pods[pod.GetId()] = state
	return gate, state
}

// The enforcer protects a pod with its own network namespace outside the
// exempt namespaces, and nothing else: a pod sharing the node's networking
// cannot be a member pod.
func TestMeshGateHostsOnlyOwnNamespacePods(t *testing.T) {
	gate, _ := gateWithPod(meshPod("default", "pod", testNetNS))
	for _, tc := range []struct {
		name  string
		pod   *api.PodSandbox
		hosts bool
	}{
		{name: "own namespace", pod: meshPod("default", "pod", testNetNS), hosts: true},
		{name: "node networking", pod: makePod("default", "host-network")},
		{name: "namespace without a path", pod: meshPod("default", "pod", "")},
		{name: "exempt namespace", pod: meshPod("kube-system", "canal", testNetNS)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := gate.hosts(tc.pod); got != tc.hosts {
				t.Fatalf("hosts = %v, want %v", got, tc.hosts)
			}
		})
	}
	if newMeshGate(nil, discardLogger()).hosts(meshPod("default", "pod", testNetNS)) {
		t.Fatal("a node with no mesh policy hosts a member pod")
	}
}

// The gate's own record decides before any ruleset is read: an unprotected or
// refused sandbox, a namespace that moved, a container out of role order, a
// reserved identity, a frozen set and a namespace-moving adjustment are each a
// refusal.
func TestMeshGateRefusals(t *testing.T) {
	workload := &api.Container{Name: "app", User: &api.User{Uid: testWorkloadUID}}
	for _, tc := range []struct {
		name    string
		arrange func(*meshGate, *protectedPod, *api.PodSandbox)
		ctr     *api.Container
		launch  gatedContainer
		wants   string
	}{
		{
			name:  "no protection installed",
			ctr:   workload,
			wants: "installed no packet protection",
			arrange: func(g *meshGate, _ *protectedPod, pod *api.PodSandbox) {
				delete(g.pods, pod.GetId())
			},
		},
		{
			name:    "refused for life",
			ctr:     workload,
			wants:   "refused for its life",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) { s.refusal = errors.New("install failed") },
		},
		{
			name:  "namespace moved",
			ctr:   workload,
			wants: "moved",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.netns.path = "/run/netns/cni-other"
			},
		},
		{
			name:  "workload before the mesh endpoint",
			ctr:   workload,
			wants: "mesh endpoint is not running",
		},
		{
			name:   "role after a workload",
			ctr:    &api.Container{Name: "c8s-cert", User: &api.User{Uid: testCertUID}},
			launch: gatedContainer{role: testCertRole},
			wants:  "after a container outside every platform role",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.meshStarted = true
				s.workloadCreated = true
			},
		},
		{
			name:    "workload claiming a reserved identity",
			ctr:     &api.Container{Name: "app", User: &api.User{Uid: testMeshUID}},
			wants:   "reserved for the mesh role",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) { s.meshStarted = true },
		},
		{
			name:  "container outside a frozen set",
			ctr:   &api.Container{Name: "debugger", User: &api.User{Uid: testWorkloadUID}},
			wants: "frozen",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.meshStarted = true
				s.frozen = true
			},
		},
		{
			name:    "adjustment re-pointing the namespaces",
			ctr:     workload,
			wants:   "re-points the container's namespaces",
			launch:  gatedContainer{namespaces: []*api.LinuxNamespace{{Type: "network", Path: "/proc/1/ns/net"}}},
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) { s.meshStarted = true },
		},
		{
			name:    "adjustment moving a host network device in",
			ctr:     workload,
			wants:   "moves a host network device in",
			launch:  gatedContainer{netDevices: map[string]*api.LinuxNetDevice{"eth9": {Name: "eth9"}}},
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) { s.meshStarted = true },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := meshPod("default", "pod", testNetNS)
			gate, state := gateWithPod(pod)
			if tc.arrange != nil {
				tc.arrange(gate, state, pod)
			}
			_, err := gate.admissible(pod, tc.ctr, tc.launch)
			if err == nil {
				t.Fatalf("admitted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// The mesh endpoint starts before the rest of the pod, a restart of an
// already-admitted container passes a frozen set, and an assertion is refused
// until a verified mesh endpoint runs.
func TestMeshGateAdmitsThePodInOrder(t *testing.T) {
	pod := meshPod("default", "pod", testNetNS)
	gate, state := gateWithPod(pod)
	mesh := &api.Container{Name: "c8s-mesh", User: &api.User{Uid: testMeshUID}}
	if _, err := gate.admissible(pod, mesh, gatedContainer{role: meshRole}); err != nil {
		t.Fatalf("the mesh endpoint was refused before its own start: %v", err)
	}
	if _, err := gate.memberNamespace(pod.GetId()); err == nil {
		t.Fatal("a sandbox with no running mesh endpoint was verified as a member")
	}

	gate.noteMeshStarted(pod.GetId())
	workload := &api.Container{Name: "app", User: &api.User{Uid: testWorkloadUID}}
	launch := gatedContainer{digest: pushDigestA}
	if _, err := gate.admissible(pod, workload, launch); err != nil {
		t.Fatalf("a workload was refused behind a running mesh endpoint: %v", err)
	}
	if _, err := gate.memberNamespace(pod.GetId()); err != nil {
		t.Fatalf("a protected pod with a running mesh endpoint is no member: %v", err)
	}
	// A container is on the record only once it has been admitted, which
	// admit does after the live ruleset verifies.
	if len(state.launched) != 0 || state.workloadCreated {
		t.Fatal("a container that is still being decided on is already on the pod's record")
	}
	gate.noteLaunched(pod.GetId(), workload.GetName(), launch)

	gate.freeze(pod.GetId())
	if _, err := gate.admissible(pod, workload, launch); err != nil {
		t.Fatalf("a restart of an admitted container was refused: %v", err)
	}
	if _, err := gate.admissible(pod, workload, gatedContainer{digest: pushDigestB}); err == nil {
		t.Fatal("a frozen set admitted the same name on another image")
	}
	if !state.frozen {
		t.Fatal("the container set was not frozen")
	}

	gate.forget(pod.GetId())
	if _, err := gate.admissible(pod, workload, launch); err == nil {
		t.Fatal("a forgotten sandbox still carries protection")
	}
}

// A pod that serves a role's own ports holds role containers only: nothing
// else in it could bind that role's listen port first (MM5, Router R9).
func TestMeshGateKeepsAServerRolePodRoleOnly(t *testing.T) {
	policy := meshRoles()
	policy.Roles = append(policy.Roles, roleBinding{
		Name:         routerRole,
		UID:          testRouterUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort("10.43.0.5:8443")},
	})
	pod := meshPod("default", "router", testNetNS)
	gate := newMeshGate(policy, discardLogger())
	gate.pods[pod.GetId()] = &protectedPod{netns: podNamespace{path: testNetNS, id: fileID{device: 3, inode: 7}}, meshStarted: true}

	router := &api.Container{Name: "nginx", User: &api.User{Uid: testRouterUID}}
	launch := gatedContainer{role: routerRole, digest: pushDigestB}
	if _, err := gate.admissible(pod, router, launch); err != nil {
		t.Fatalf("the router role was refused in its own pod: %v", err)
	}
	gate.noteLaunched(pod.GetId(), router.GetName(), launch)
	workload := &api.Container{Name: "app", User: &api.User{Uid: testWorkloadUID}}
	_, err := gate.admissible(pod, workload, gatedContainer{digest: pushDigestA})
	if err == nil {
		t.Fatal("a workload joined a pod that serves the router's own ports")
	}
	if !strings.Contains(err.Error(), "only its platform roles may run here") {
		t.Fatalf("error = %v, want the role-only rule", err)
	}

	// A pod without such a role keeps running workloads.
	plain := meshPod("default", "pod", testNetNS)
	plainGate, state := gateWithPod(plain)
	state.meshStarted = true
	if _, err := plainGate.admissible(plain, workload, gatedContainer{digest: pushDigestA}); err != nil {
		t.Fatalf("a workload was refused in a pod with no server role: %v", err)
	}
}

// A sandbox that was running before this enforcer connected is refused for its
// life: its containers ran unchecked by it (MM2). Its record also stands, so a
// later sandbox event cannot replace it with a fresh one.
func TestMeshGateRefusesSandboxesItDidNotProtect(t *testing.T) {
	pod := meshPod("default", "pod", testNetNS)
	gate := newMeshGate(meshRoles(), discardLogger())
	gate.refuseExisting([]*api.PodSandbox{pod, makePod("default", "host-network")})

	workload := &api.Container{Name: "app", User: &api.User{Uid: testWorkloadUID}}
	_, err := gate.admissible(pod, workload, gatedContainer{digest: pushDigestA})
	if err == nil || !strings.Contains(err.Error(), "before this enforcer connected") {
		t.Fatalf("error = %v, want the pre-existing sandbox refusal", err)
	}
	if err := gate.protect(pod); err == nil || !strings.Contains(err.Error(), "on record already") {
		t.Fatalf("protect replaced the record of a refused sandbox: %v", err)
	}
	if err := gate.verifyMember(pod.GetId()); err == nil {
		t.Fatal("a sandbox this enforcer never protected was verified as a member")
	}
}

// An assertion needs the gate's verification of the caller's pod: the plugin
// answers with a refusal until it has one, and a node with no mesh policy has
// no protection to withhold (B4). A signed assertion freezes the pod's set.
func TestSandboxForPeerRequiresVerifiedProtection(t *testing.T) {
	procRoot := t.TempDir()
	pod := meshPod("default", "pod", testNetNS)
	gate, state := gateWithPod(pod)
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.mesh = gate
	p.inventory = newAdmissionInventory(procRoot)
	p.inventory.record(cidGetCert, pod.GetId(), "c8s-cert", digestOther, nil, nil)
	writeCgroup(t, procRoot, 4242, cidGetCert)

	caller, err := p.SandboxForPeer(workloadclaims.PeerForPID(4242))
	if err != nil {
		t.Fatal(err)
	}
	if caller.SandboxID != pod.GetId() {
		t.Fatalf("sandbox = %q, want %q", caller.SandboxID, pod.GetId())
	}
	if caller.Refusal == nil {
		t.Fatal("a sandbox with no running mesh endpoint was answered without a refusal")
	}

	state.refusal = errors.New("install failed")
	gate.noteMeshStarted(pod.GetId())
	if caller, err = p.SandboxForPeer(workloadclaims.PeerForPID(4242)); err != nil || caller.Refusal == nil {
		t.Fatalf("a refused sandbox was answered without a refusal: %v %v", caller, err)
	}

	// A node whose measured config carries no mesh policy hosts no member
	// pods, so it withholds nothing.
	p.mesh = newMeshGate(nil, discardLogger())
	caller, err = p.SandboxForPeer(workloadclaims.PeerForPID(4242))
	if err != nil || caller.Refusal != nil {
		t.Fatalf("a node with no mesh policy withheld an assertion: %v %v", caller, err)
	}
}

// The validator is the hook the gate runs on, and its refusal does not depend
// on policy.mode: an audit-mode plugin still refuses a container whose pod has
// no verified protection.
func TestValidateContainerAdjustmentGatesOnProtection(t *testing.T) {
	base := roleBase(t, pushDigestB, testCertRole, []string{"/usr/local/bin/c8s"})
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: base, NodeTCB: true},
		Policy:    policyConfig{Mode: ModeAudit},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.mesh = newMeshGate(meshRoles(), discardLogger())
	p.SetReady()

	pod := meshPod("default", "pod", testNetNS)
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestA)
	err := p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr})
	if err == nil {
		t.Fatal("a container of an unprotected pod was admitted")
	}
	if !strings.Contains(err.Error(), "mesh gate") {
		t.Fatalf("error = %v, want the mesh gate to name itself", err)
	}

	// A pod outside the mesh's scope keeps the admission path it had.
	exempt := meshPod("kube-system", "canal", testNetNS)
	exemptCtr := makeCtrWithImage(exempt.Id, "canal", "registry/repo@"+pushDigestA)
	if err := p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{Pod: exempt, Container: exemptCtr}); err != nil {
		t.Fatalf("an exempt pod was gated: %v", err)
	}
}

// A protected pod's containers cannot be changed once it runs (MP2).
func TestUpdateContainerRefusedForProtectedPods(t *testing.T) {
	pod := meshPod("default", "pod", testNetNS)
	gate, _ := gateWithPod(pod)
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.mesh = gate

	ctr := makeCtr(pod.Id, "app")
	if _, err := p.UpdateContainer(context.Background(), pod, ctr, nil); err == nil {
		t.Fatal("a protected pod's container was updated")
	}
	if _, err := p.UpdateContainer(context.Background(), makePod("default", "host-network"), ctr, nil); err != nil {
		t.Fatalf("a pod outside the mesh's scope was refused an update: %v", err)
	}
}

// The gate subscribes to the events it needs, and a node with no mesh policy
// subscribes to none of them.
func TestConfigureSubscribesMeshEvents(t *testing.T) {
	p := newTestPlugin(&config{})
	mask, err := p.Configure(context.Background(), "", "containerd", "2.0")
	if err != nil {
		t.Fatal(err)
	}
	if mask.IsSet(api.Event_UPDATE_CONTAINER) {
		t.Fatal("container updates subscribed without a mesh policy")
	}
	if !mask.IsSet(api.Event_VALIDATE_CONTAINER_ADJUSTMENT) {
		t.Fatal("the plugin does not register as a validator")
	}

	p.mesh = newMeshGate(&meshPolicy{}, discardLogger())
	mask, err = p.Configure(context.Background(), "", "containerd", "2.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []api.Event{api.Event_RUN_POD_SANDBOX, api.Event_REMOVE_POD_SANDBOX, api.Event_UPDATE_CONTAINER, api.Event_VALIDATE_CONTAINER_ADJUSTMENT} {
		if !mask.IsSet(event) {
			t.Fatalf("event %v not subscribed with a mesh policy", event)
		}
	}
}

// A role lookup never reads the pod's own metadata, so a workload cannot
// impersonate the get-cert role by name or annotation.
func TestPodMetadataGrantsNoRole(t *testing.T) {
	argv := []string{"/usr/local/bin/c8s", "get-cert"}
	base := roleBase(t, pushDigestB, testCertRole, argv)
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: base, NodeTCB: true},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))

	impostor := allowlist.RunningContainer{Digest: pushDigestA, Argv: argv}
	if got := p.roleOf(impostor); got != "" {
		t.Fatalf("an impostor took the %q role", got)
	}
}
