package nriimagepolicy

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// testNetNS is a namespace path the state tests never open: they drive the
// enforcer's own record, which decides before any ruleset is read.
const testNetNS = "/run/netns/cni-test"

// gateCtr is a container as the gate sees one: its name, the identity it runs
// as, and the pid namespace of its own every container of a member pod holds.
func gateCtr(name string, uid uint32) *api.Container {
	return &api.Container{
		Name:  name,
		User:  &api.User{Uid: uid},
		Linux: &api.LinuxContainer{Namespaces: []*api.LinuxNamespace{{Type: pidNamespace}}},
	}
}

// meshPod is a pod with its own network namespace, as containerd reports one.
func meshPod(namespace, name, netnsPath string) *api.PodSandbox {
	pod := makePod(namespace, name)
	pod.Pid = 4242
	pod.Linux = &api.LinuxPodSandbox{Namespaces: []*api.LinuxNamespace{
		{
			Type: "pid",
			Path: "/proc/4242/ns/pid",
		},
		{
			Type: "network",
			Path: netnsPath,
		},
	}}
	return pod
}

// gateWithPod returns a gate already holding a protected sandbox, so the
// state rules can be exercised without a kernel namespace.
func gateWithPod(pod *api.PodSandbox) (*meshGate, *protectedPod) {
	gate := newMeshGate(meshRoles(), slog.Default())
	state := &protectedPod{
		netns:         testNamespace(),
		kubeNamespace: pod.GetNamespace(),
	}
	gate.pods[pod.GetId()] = state
	return gate, state
}

// testNamespace is the namespace on a protected pod's record.
func testNamespace() podNamespace {
	return podNamespace{
		path: testNetNS,
		id: fileID{
			device: 3,
			inode:  7,
		},
	}
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
// reserved identity and a namespace-moving adjustment are each a refusal.
func TestMeshGateRefusals(t *testing.T) {
	workload := gateCtr("app", testWorkloadUID)
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
			name:  "refused for life",
			ctr:   workload,
			wants: "refused for its life",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.refusal = errors.New("install failed")
			},
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
			ctr:    gateCtr("c8s-cert", testCertUID),
			launch: gatedContainer{role: testCertRole},
			wants:  "after a container outside every platform role",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.meshStarted = true
				s.workloadCreated = true
			},
		},
		{
			name:  "workload claiming a reserved identity",
			ctr:   gateCtr("app", testMeshUID),
			wants: "reserved for the mesh role",
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.meshStarted = true
			},
		},
		{
			name:   "adjustment re-pointing the namespaces",
			ctr:    workload,
			wants:  "re-points the container's namespaces",
			launch: gatedContainer{namespaces: []*api.LinuxNamespace{{Type: "network", Path: "/proc/1/ns/net"}}},
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.meshStarted = true
			},
		},
		{
			name:   "adjustment moving a host network device in",
			ctr:    workload,
			wants:  "moves a host network device in",
			launch: gatedContainer{netDevices: map[string]*api.LinuxNetDevice{"eth9": {Name: "eth9"}}},
			arrange: func(_ *meshGate, s *protectedPod, _ *api.PodSandbox) {
				s.meshStarted = true
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := meshPod("default", "pod", testNetNS)
			gate, state := gateWithPod(pod)
			if tc.arrange != nil {
				tc.arrange(gate, state, pod)
			}
			_, _, err := gate.admissible(pod, tc.ctr, tc.launch)
			if err == nil {
				t.Fatalf("admitted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// The mesh endpoint starts before the rest of the pod, an assertion is
// refused until a verified mesh endpoint runs, and a container that joins
// later is admitted on its own role, order and identity.
func TestMeshGateAdmitsThePodInOrder(t *testing.T) {
	pod := meshPod("default", "pod", testNetNS)
	gate, state := gateWithPod(pod)
	mesh := gateCtr("c8s-mesh", testMeshUID)
	if _, _, err := gate.admissible(pod, mesh, gatedContainer{role: meshRole}); err != nil {
		t.Fatalf("the mesh endpoint was refused before its own start: %v", err)
	}
	if _, _, err := gate.memberNamespace(pod.GetId()); err == nil {
		t.Fatal("a sandbox with no running mesh endpoint was verified as a member")
	}

	gate.noteMeshStarted(pod.GetId())
	workload := gateCtr("app", testWorkloadUID)
	launch := gatedContainer{}
	if _, _, err := gate.admissible(pod, workload, launch); err != nil {
		t.Fatalf("a workload was refused behind a running mesh endpoint: %v", err)
	}
	if _, _, err := gate.memberNamespace(pod.GetId()); err != nil {
		t.Fatalf("a protected pod with a running mesh endpoint is no member: %v", err)
	}
	// A container is on the record only once it has been admitted, which
	// admit does after the live ruleset verifies.
	if state.workloadCreated {
		t.Fatal("a container that is still being decided on is already on the pod's record")
	}
	gate.noteLaunched(pod.GetId(), launch)

	// The pod's own containers are created after its mesh endpoint holds an
	// identity, so a name the record has never seen still joins.
	joiner := gateCtr("sidecar", testWorkloadUID)
	if _, _, err := gate.admissible(pod, joiner, gatedContainer{}); err != nil {
		t.Fatalf("a container joining a pod that holds an identity was refused: %v", err)
	}

	gate.forget(pod.GetId())
	if _, _, err := gate.admissible(pod, workload, launch); err == nil {
		t.Fatal("a forgotten sandbox still carries protection")
	}
}

// A platform-role container the gate admitted runs again after the pod's
// applications started, which is how a crashed role is replaced; any other
// bytes, arguments or role under that pod stay refused.
func TestMeshGateAdmitsAnAdmittedRoleLaunchAgain(t *testing.T) {
	pod := meshPod("default", "pod", testNetNS)
	gate, state := gateWithPod(pod)
	cert := gateCtr("c8s-cert", testCertUID)
	launch := gatedContainer{
		role:   testCertRole,
		digest: pushDigestA,
		argv:   []string{"/usr/bin/c8s", "get-cert"},
	}
	gate.noteMeshStarted(pod.GetId())
	if _, _, err := gate.admissible(pod, cert, launch); err != nil {
		t.Fatalf("a role container was refused ahead of the pod's applications: %v", err)
	}
	gate.noteLaunched(pod.GetId(), launch)
	gate.noteLaunched(pod.GetId(), gatedContainer{})
	if !state.workloadCreated {
		t.Fatal("an admitted workload is not on the pod's record")
	}

	if _, _, err := gate.admissible(pod, cert, launch); err != nil {
		t.Fatalf("a replacement of an admitted role launch was refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		launch gatedContainer
	}{
		{
			name: "another image",
			launch: gatedContainer{
				role:   testCertRole,
				digest: pushDigestB,
				argv:   launch.argv,
			},
		},
		{
			name: "another argument",
			launch: gatedContainer{
				role:   testCertRole,
				digest: pushDigestA,
				argv:   []string{"/usr/bin/c8s", "get-cert", "--once"},
			},
		},
		{
			name: "a role that never ran here",
			launch: gatedContainer{
				role:   meshRole,
				digest: pushDigestA,
				argv:   launch.argv,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := gate.admissible(pod, cert, tc.launch)
			if err == nil {
				t.Fatalf("admitted %s after the pod's applications started", tc.name)
			}
			if !strings.Contains(err.Error(), "after a container outside every platform role") {
				t.Fatalf("error = %v, want it to name the role order", err)
			}
		})
	}
}

// A pod of the router's namespace holds role containers only: nothing else in
// it could bind the router's listen port first.
func TestMeshGateKeepsARouterNamespacePodRoleOnly(t *testing.T) {
	policy := meshRoles()
	pod := meshPod(routerNamespace, "router", testNetNS)
	gate := newMeshGate(policy, discardLogger())
	gate.pods[pod.GetId()] = &protectedPod{
		netns:         testNamespace(),
		meshStarted:   true,
		kubeNamespace: pod.GetNamespace(),
	}

	router := gateCtr("nginx", testRouterUID)
	launch := gatedContainer{
		role:         routerRole,
		mountsPinned: true,
	}
	if _, _, err := gate.admissible(pod, router, launch); err != nil {
		t.Fatalf("the router role was refused in its own pod: %v", err)
	}
	gate.noteLaunched(pod.GetId(), launch)
	workload := gateCtr("app", testWorkloadUID)
	_, _, err := gate.admissible(pod, workload, gatedContainer{})
	if err == nil {
		t.Fatal("a workload joined a pod that serves the router's own ports")
	}
	if !strings.Contains(err.Error(), "only its platform roles may run here") {
		t.Fatalf("error = %v, want the role-only rule", err)
	}

	// The credentials of this pod are separated by mount set, so a role
	// container the base admits with its mounts left to the host — the shape
	// that would compose a second reader of the front door's key — is refused
	// here.
	composed := gatedContainer{role: testCertRole}
	_, _, err = gate.admissible(pod, gateCtr("c8s-cert", testCertUID), composed)
	if err == nil {
		t.Fatal("a role container with unpinned mounts joined the router's pod")
	}
	if !strings.Contains(err.Error(), "pins its mounts") {
		t.Fatalf("error = %v, want the pinned-mounts rule", err)
	}

	// A pod of any other namespace keeps running workloads.
	plain := meshPod("default", "pod", testNetNS)
	plainGate, state := gateWithPod(plain)
	state.meshStarted = true
	if _, _, err := plainGate.admissible(plain, workload, gatedContainer{}); err != nil {
		t.Fatalf("a workload was refused in a pod outside the router's namespace: %v", err)
	}
}

// A member pod's container runs in a pid namespace of its own. With a shared
// one every process of the pod is in one /proc, where a container reads
// another's credential volume at /proc/<pid>/root whatever the mount sets
// pin; containerd points the namespace at a process only when the pod shares
// it, and leaves the entry out when the pod uses the node's.
func TestMeshGateRefusesASharedPIDNamespace(t *testing.T) {
	pod := meshPod(routerNamespace, "router", testNetNS)
	for name, namespaces := range map[string][]*api.LinuxNamespace{
		"the pod's own, shared": {{
			Type: pidNamespace,
			Path: "/proc/4242/ns/pid",
		}},
		"the node's": {{Type: "ipc"}},
	} {
		t.Run(name, func(t *testing.T) {
			gate, state := gateWithPod(pod)
			state.meshStarted = true
			shared := gateCtr("nginx", testRouterUID)
			shared.Linux = &api.LinuxContainer{Namespaces: namespaces}
			launch := gatedContainer{
				role:         routerRole,
				mountsPinned: true,
			}
			_, _, err := gate.admissible(pod, shared, launch)
			if err == nil {
				t.Fatal("a member pod's container was admitted outside a pid namespace of its own")
			}
			if !strings.Contains(err.Error(), "pid namespace") {
				t.Fatalf("error = %v, want the pid-namespace rule", err)
			}
		})
	}
}

// A sandbox that was running before this enforcer connected is refused for its
// life: its containers ran unchecked by it. Its record also stands, so a later
// sandbox event cannot replace it with a fresh one.
func TestMeshGateRefusesSandboxesItDidNotProtect(t *testing.T) {
	pod := meshPod("default", "pod", testNetNS)
	gate := newMeshGate(meshRoles(), discardLogger())
	gate.refuseExisting([]*api.PodSandbox{pod, makePod("default", "host-network")})

	workload := gateCtr("app", testWorkloadUID)
	_, _, err := gate.admissible(pod, workload, gatedContainer{})
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
// no protection to withhold.
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
	// The digests of that sandbox are the inventory's, so a refused caller
	// and its pod's contents are answered from the same record.
	digests, _, known, err := p.DigestsForSandbox(pod.GetId())
	if err != nil || !known {
		t.Fatalf("the plugin does not answer for a sandbox it tracks: %v %v", known, err)
	}
	if len(digests) != 1 || digests[0] != digestOther {
		t.Fatalf("digests = %v, want the container the inventory recorded", digests)
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

// A container the enforcer refused keeps its whole sandbox from asserting an
// identity: the refusal is the plugin's answer ahead of the gate's
// verification, so the admitted rest of the pod holds no mesh certificate.
func TestSandboxForPeerRefusesASandboxWithADeniedContainer(t *testing.T) {
	procRoot := t.TempDir()
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()
	pod := meshPod("default", "pod", testNetNS)
	gate, _ := gateWithPod(pod)
	gate.noteMeshStarted(pod.GetId())
	p.mesh = gate
	p.inventory = newAdmissionInventory(procRoot)
	p.inventory.record(cidGetCert, pod.GetId(), "c8s-cert", digestOther, nil, nil)
	writeCgroup(t, procRoot, 4242, cidGetCert)

	denied := makeCtrWithImage(pod.GetId(), "app", "registry/repo@"+pushDigestB)
	if _, _, err := p.CreateContainer(context.Background(), pod, denied); err == nil {
		t.Fatal("a container outside the allowlist was created")
	}

	caller, err := p.SandboxForPeer(workloadclaims.PeerForPID(4242))
	if err != nil {
		t.Fatal(err)
	}
	if caller.Refusal == nil {
		t.Fatal("a sandbox with a denied container was answered without a refusal")
	}
	if !strings.Contains(caller.Refusal.Error(), "not in allowlist") {
		t.Fatalf("refusal = %v, want the denied container's own reason", caller.Refusal)
	}

	// The sandbox still reports what ran in it.
	digests, _, known, err := p.DigestsForSandbox(pod.GetId())
	if err != nil || !known {
		t.Fatalf("the plugin does not answer for a sandbox it tracks: %v %v", known, err)
	}
	if len(digests) != 1 || digests[0] != digestOther {
		t.Fatalf("digests = %v, want the container the inventory recorded", digests)
	}

	// The refusal goes with the sandbox.
	if err := p.RemovePodSandbox(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if p.inventory.denial(pod.GetId()) != nil {
		t.Fatal("a removed sandbox kept its refusal")
	}
}

// The validator is the hook the gate runs on, and its refusal does not depend
// on policy.mode: an audit-mode plugin still refuses a container whose pod has
// no verified protection.
func TestValidateContainerAdjustmentGatesOnProtection(t *testing.T) {
	base := roleBase(t, pushDigestB, testCertRole, []string{"/usr/local/bin/c8s"})
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{
			Base:    base,
			NodeTCB: true,
		},
		Policy: policyConfig{Mode: ModeAudit},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.mesh = newMeshGate(meshRoles(), discardLogger())
	p.SetReady()

	pod := meshPod("default", "pod", testNetNS)
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestA)
	err := p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{
		Pod:       pod,
		Container: ctr,
	})
	if err == nil {
		t.Fatal("a container of an unprotected pod was admitted")
	}
	if !strings.Contains(err.Error(), "mesh gate") {
		t.Fatalf("error = %v, want the mesh gate to name itself", err)
	}

	// A pod outside the mesh's scope keeps the admission path it had.
	exempt := meshPod("kube-system", "canal", testNetNS)
	exemptCtr := makeCtrWithImage(exempt.Id, "canal", "registry/repo@"+pushDigestA)
	exemptReq := &api.ValidateContainerAdjustmentRequest{
		Pod:       exempt,
		Container: exemptCtr,
	}
	if err := p.ValidateContainerAdjustment(context.Background(), exemptReq); err != nil {
		t.Fatalf("an exempt pod was gated: %v", err)
	}
}

// A declaration pins the mount set the pod asks for: the bind this enforcer
// adds itself leaves it standing, while a mount of the pod's own at the same
// destination counts and does not match the declaration.
func TestValidateContainerAdjustmentPinsThePodsOwnMounts(t *testing.T) {
	const enforcerAddress = "/run/c8s-enforcer/cds-address"
	base := roleBase(t, pushDigestB, testCertRole, []string{"/c8s", "get-cert"})
	base.Workloads["pinned-entry"] = allowlist.Workload{Containers: []allowlist.Container{{
		Digest: mustDigest(t, pushDigestB),
		Role:   testCertRole,
		Command: allowlist.ArgvPolicy{
			Policy: allowlist.PolicyExact,
			Argv:   []string{"/c8s", "get-cert"},
		},
		Args: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts: allowlist.MountPolicy{
			Policy: allowlist.PolicyExact,
			Rules: []allowlist.MountRule{{
				Destination: "/run/c8s-node",
				Kind:        allowlist.MountHost,
				Source:      "/run/c8s-node",
				ReadOnly:    true,
			}},
		},
	}}}
	for _, tc := range []struct {
		name     string
		declared []*api.Mount
		adjust   []*api.Mount
		pinned   bool
	}{
		{
			name:   "the enforcer's own bind",
			adjust: []*api.Mount{readOnlyBind(enforcerAddress, workloadclaims.CDSAddressPath)},
			pinned: true,
		},
		{
			name:     "a mount of the pod's own at that destination",
			declared: []*api.Mount{readOnlyBind("/run/c8s-elsewhere", workloadclaims.CDSAddressPath)},
			pinned:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newCachedPlugin(&config{
				Allowlist: allowlistConfig{
					Base:    base,
					NodeTCB: true,
				},
				Policy: policyConfig{Mode: ModeAudit},
			}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
			p.cdsAddress = enforcerAddress
			pod := meshPod(routerNamespace, "c8s-router", testNetNS)
			gate, state := gateWithPod(pod)
			state.meshStarted = true
			p.mesh = gate
			p.SetReady()

			ctr := gateCtr("c8s-cert", testCertUID)
			ctr.PodSandboxId = pod.GetId()
			ctr.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestB}
			ctr.Args = []string{"/c8s", "get-cert", "--san=c8s-router.c8s-router.svc"}
			ctr.Mounts = append([]*api.Mount{readOnlyBind("/run/c8s-node", "/run/c8s-node")}, tc.declared...)
			req := &api.ValidateContainerAdjustmentRequest{
				Pod:       pod,
				Container: ctr,
				Adjust:    &api.ContainerAdjustment{Mounts: tc.adjust},
			}
			err := p.ValidateContainerAdjustment(context.Background(), req)
			if err == nil {
				t.Fatal("the gate admitted a container without reading the pod's ruleset")
			}
			if strings.Contains(err.Error(), "pins its mounts") == tc.pinned {
				t.Fatalf("error = %v, pinned mount set = %t", err, tc.pinned)
			}
		})
	}
}

// A protected pod's containers cannot be changed once it runs.
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
		Allowlist: allowlistConfig{
			Base:    base,
			NodeTCB: true,
		},
		Policy: policyConfig{Mode: ModeFailClosed},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))

	impostor := allowlist.RunningContainer{
		Digest: pushDigestA,
		Argv:   argv,
	}
	if got := p.roleOf(impostor); got != "" {
		t.Fatalf("an impostor took the %q role", got)
	}
	// A plugin that holds no policy at all binds no role either.
	if got := newTestPlugin(&config{}).roleOf(impostor); got != "" {
		t.Fatalf("a plugin with no policy bound the %q role", got)
	}
}

// The mesh endpoint's start is what opens a protected pod's gate, and the
// enforcer reads that start from the verified identity of the container that
// started — not from its name.
func TestStartContainerOpensTheGateOnTheMeshEndpointAlone(t *testing.T) {
	argv := []string{"/usr/local/bin/armtls-mesh"}
	base := roleBase(t, pushDigestB, meshRole, argv)
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{
			Base:    base,
			NodeTCB: true,
		},
		Policy: policyConfig{
			Mode:          ModeFailClosed,
			FatalExisting: true,
		},
	}, base)
	p.SetReady()
	pod := meshPod("default", "pod", testNetNS)
	gate, state := gateWithPod(pod)
	p.mesh = gate

	impostor := makeCtrWithImageArgs(pod.Id, "c8s-mesh", "registry/repo@"+pushDigestA, argv)
	if err := p.StartContainer(context.Background(), pod, impostor); err != nil {
		t.Fatalf("a container admitted by the served allowlist was refused: %v", err)
	}
	if state.meshStarted {
		t.Fatal("a container named after the mesh endpoint opened the pod's gate")
	}

	mesh := makeCtrWithImageArgs(pod.Id, "sidecar", "registry/repo@"+pushDigestB, argv)
	if err := p.StartContainer(context.Background(), pod, mesh); err != nil {
		t.Fatalf("the pod's mesh endpoint was refused: %v", err)
	}
	if !state.meshStarted {
		t.Fatal("the pod's mesh endpoint did not open its gate")
	}

	// A pod the mesh does not host has no gate to open.
	exempt := meshPod("kube-system", "canal", testNetNS)
	if err := p.StartContainer(context.Background(), exempt, mesh); err != nil {
		t.Fatalf("a pod outside the mesh's scope was refused: %v", err)
	}
}

// The install that deploys CDS deploys the router too, so a member pod's
// containers are created while the enforcer is still initializing. The gate
// refuses them until the pod's own endpoint has started, so that start is
// recorded on the initializing path as well — otherwise the endpoint runs and
// the rest of the pod is refused for the sandbox's life.
func TestMeshEndpointStartOpensTheGateWhileInitializing(t *testing.T) {
	const meshImage = "registry/repo@" + pushDigestB
	p, _ := newCachedPlugin(&config{
		Policy: policyConfig{Mode: ModeFailClosed},
		Allowlist: allowlistConfig{
			Base: roleBase(t, pushDigestB, meshRole, []string{"/app/c8s", "armtls-mesh"}),
			Pull: pullConfig{URL: "https://cds"},
		},
	}, anyAllowlist(map[string]string{pushDigestA: "served"}))
	pod := meshPod("default", "pod", testNetNS)
	gate, state := gateWithPod(pod)
	p.mesh = gate
	endpoint := makeCtrWithImageArgs(pod.GetId(), "c8s-mesh", meshImage,
		[]string{"/app/c8s", "armtls-mesh", "--cert-path=/etc/c8s/certs/tls.crt"})
	endpoint.User = &api.User{Uid: testMeshUID}

	if p.Ready() {
		t.Fatal("the plugin is ready, so this is not the initializing path")
	}
	if err := p.StartContainer(context.Background(), pod, endpoint); err != nil {
		t.Fatalf("the mesh endpoint was refused while the enforcer was initializing: %v", err)
	}
	if !state.meshStarted {
		t.Fatal("the mesh endpoint started without opening the gate for the rest of the pod")
	}

	cert := gateCtr("c8s-cert", testCertUID)
	if _, _, err := gate.admissible(pod, cert, gatedContainer{role: testCertRole}); err != nil {
		t.Fatalf("a role container was refused behind a started mesh endpoint: %v", err)
	}
}
