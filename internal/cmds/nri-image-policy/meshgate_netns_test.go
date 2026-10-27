//go:build linux

package nriimagepolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
)

// requireNetNS fails rather than skips when C8S_REQUIRE_NFT is set, which is
// how CI runs these tests: a namespace it cannot create must not leave the
// enforcer's install and verify paths silently untested. Verification walks
// BPF link ids and queries interface hooks, which need CAP_BPF and
// CAP_NET_ADMIN in the initial user namespace, so uid 0 in a user namespace
// of its own is not enough — the enforcer runs as the node's own root.
func requireNetNS(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 && inInitialUserNamespace() {
		return
	}
	const reason = "needs the node's own root (uid 0 in the initial user namespace): run under sudo"
	if os.Getenv("C8S_REQUIRE_NFT") == "1" {
		t.Fatal(reason)
	}
	t.Skip(reason)
}

// inInitialUserNamespace reports the identity mapping only the initial user
// namespace carries.
func inInitialUserNamespace() bool {
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	return strings.Join(strings.Fields(string(mapping)), " ") == "0 0 4294967295"
}

// sandboxProcess starts a process in a network namespace of its own and
// returns its PID: that is what a pod sandbox is to the enforcer — a process
// whose namespace the pod's containers join.
func sandboxProcess(t *testing.T) uint32 {
	t.Helper()
	requireNetNS(t)
	sandbox := exec.Command("sleep", "600")
	sandbox.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	if err := sandbox.Start(); err != nil {
		t.Fatalf("start a sandbox process in its own network namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = sandbox.Process.Kill()
		_, _ = sandbox.Process.Wait()
	})
	return uint32(sandbox.Process.Pid)
}

func sandboxNetNSPath(pid uint32) string {
	return fmt.Sprintf("/proc/%d/ns/net", pid)
}

// The ruleset is installed into the pod's own namespace only when the path the
// runtime reports is proven to be that sandbox's: anything else would protect
// a namespace that carries none of the pod's traffic.
func TestProveSandboxNamespaceInTheNamespace(t *testing.T) {
	pid := sandboxProcess(t)
	other := sandboxProcess(t)
	regular := t.TempDir() + "/not-a-namespace"
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		path  string
		pid   uint32
		wants string
	}{
		{name: "the sandbox's own namespace", path: sandboxNetNSPath(pid), pid: pid},
		{name: "no sandbox process", path: sandboxNetNSPath(pid), wants: "no sandbox process"},
		{name: "the node's own namespace", path: "/proc/self/ns/net", pid: pid, wants: "the node's own network namespace"},
		{name: "another sandbox's namespace", path: sandboxNetNSPath(other), pid: pid, wants: "is not the network namespace of sandbox process"},
		{name: "another kind of namespace", path: fmt.Sprintf("/proc/%d/ns/uts", pid), pid: pid, wants: "is not the network namespace of sandbox process"},
		{name: "a regular file", path: regular, pid: pid, wants: "is not the network namespace of sandbox process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proven, err := proveSandboxNamespace(tc.path, tc.pid)
			switch {
			case tc.wants == "":
				if err != nil {
					t.Fatalf("the sandbox's own namespace was refused: %v", err)
				}
				if proven.id == (fileID{}) {
					t.Fatal("a proven namespace carries no file identity")
				}
			case err == nil:
				t.Fatalf("proved %s", tc.name)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// A path that names another namespace than the one installed into is refused
// even while it exists: the rules of another namespace say nothing about this
// pod.
func TestVerifyRejectsAReplacedNamespaceInTheNamespace(t *testing.T) {
	pid := sandboxProcess(t)
	other := sandboxProcess(t)
	proven, err := proveSandboxNamespace(sandboxNetNSPath(pid), pid)
	if err != nil {
		t.Fatal(err)
	}
	replaced := podNamespace{
		path: sandboxNetNSPath(other),
		id:   proven.id,
	}
	err = verifyPodRuleset(replaced, *meshRoles(), "default", nil)
	if err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("error = %v, want the replaced-namespace refusal", err)
	}
}

// The whole gate over a real pod namespace: the sandbox's start installs the
// ruleset, the mesh endpoint runs first, every other container waits for it,
// an assertion needs the live ruleset, and a namespace that is gone refuses
// everything.
func TestProtectAndGateAPodInTheNamespace(t *testing.T) {
	pid := sandboxProcess(t)
	pod := meshPod("default", "pod", sandboxNetNSPath(pid))
	pod.Pid = pid
	gate := newMeshGate(*meshRoles(), discardLogger())

	if err := gate.protect(pod); err != nil {
		t.Fatalf("protect: %v", err)
	}
	mesh := gateCtr("c8s-mesh", testMeshUID)
	if err := gate.admit(pod, mesh, gatedContainer{role: meshRole}); err != nil {
		t.Fatalf("the mesh endpoint was refused in a protected pod: %v", err)
	}
	workload := gateCtr("app", testWorkloadUID)
	if err := gate.admit(pod, workload, gatedContainer{}); err == nil {
		t.Fatal("a workload started before the pod's mesh endpoint")
	}
	if err := gate.verifyMember(pod.GetId()); err == nil {
		t.Fatal("a pod with no running mesh endpoint was verified as a member")
	}

	gate.noteMeshStarted(pod.GetId())
	if err := gate.admit(pod, workload, gatedContainer{}); err != nil {
		t.Fatalf("a workload was refused behind a verified ruleset: %v", err)
	}
	if err := gate.verifyMember(pod.GetId()); err != nil {
		t.Fatalf("a protected member pod was refused an assertion: %v", err)
	}
	// The pod's own containers are created after its mesh endpoint holds an
	// identity, so a later container is decided on its own terms.
	later := gateCtr("sidecar", testWorkloadUID)
	if err := gate.admit(pod, later, gatedContainer{}); err != nil {
		t.Fatalf("a container joining a pod that holds an identity was refused: %v", err)
	}
	role := gateCtr("c8s-cert", testCertUID)
	if err := gate.admit(pod, role, gatedContainer{role: testCertRole}); err == nil {
		t.Fatal("a platform role joined a pod behind its workload")
	}

	// A second install into the same namespace is refused, so the pod's
	// protection cannot be replaced under a running container.
	if err := installPodRuleset(podNamespace{path: sandboxNetNSPath(pid)}, gate.policy, "default"); !errors.Is(err, ruleset.ErrForeignRules) {
		t.Fatalf("second install = %v, want ErrForeignRules", err)
	}

	// The namespace is gone once the sandbox process is: every answer about it
	// is then a refusal.
	if err := unix.Kill(int(pid), unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := waitForNamespaceGone(sandboxNetNSPath(pid)); err != nil {
		t.Fatal(err)
	}
	if err := gate.admit(pod, workload, gatedContainer{}); err == nil {
		t.Fatal("a container was admitted into a namespace that is gone")
	}
	if err := gate.verifyMember(pod.GetId()); err == nil {
		t.Fatal("a sandbox whose namespace is gone was verified as a member")
	}
}

// A restarted enforcer takes a protected pod back under the gate; a sandbox
// holding no ruleset is refused for its life.
func TestRecoverAProtectedPodInTheNamespace(t *testing.T) {
	pid := sandboxProcess(t)
	pod := meshPod("default", "pod", sandboxNetNSPath(pid))
	pod.Pid = pid
	before := newMeshGate(*meshRoles(), discardLogger())
	if err := before.protect(pod); err != nil {
		t.Fatalf("protect: %v", err)
	}
	mesh := gateCtr("c8s-mesh", testMeshUID)
	meshLaunch := gatedContainer{role: meshRole, digest: digestOther, argv: []string{"/app/c8s", "armtls-mesh"}}
	if err := before.admit(pod, mesh, meshLaunch); err != nil {
		t.Fatalf("admit the mesh endpoint: %v", err)
	}
	before.noteMeshStarted(pod.GetId())
	workload := gateCtr("app", testWorkloadUID)
	if err := before.admit(pod, workload, gatedContainer{}); err != nil {
		t.Fatalf("admit the workload: %v", err)
	}

	// The enforcer restarts: a new gate reads the sandbox back.
	after := newMeshGate(*meshRoles(), discardLogger())
	err := after.recoverPod(pod, []recoveredContainer{
		{ctr: mesh, launch: meshLaunch, running: true},
		{ctr: workload, running: true},
	}, recoveredExits{})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if err := after.verifyMember(pod.GetId()); err != nil {
		t.Fatalf("a recovered member pod was refused an assertion: %v", err)
	}
	later := gateCtr("sidecar", testWorkloadUID)
	if err := after.admit(pod, later, gatedContainer{}); err != nil {
		t.Fatalf("a container joining a recovered pod was refused: %v", err)
	}
	// The crashed endpoint's replacement is the launch on record, nothing else.
	if err := after.admit(pod, mesh, meshLaunch); err != nil {
		t.Fatalf("the recorded mesh launch was refused a restart: %v", err)
	}
	if err := after.admit(pod, gateCtr("c8s-cert", testCertUID), gatedContainer{role: testCertRole}); err == nil {
		t.Fatal("a platform role this gate never saw joined a recovered pod behind its workload")
	}

	// A sandbox nothing protected shows no ruleset to read back.
	bare := sandboxProcess(t)
	unprotected := meshPod("default", "bare", sandboxNetNSPath(bare))
	unprotected.Pid = bare
	if err := after.recoverPod(unprotected, nil, recoveredExits{}); err == nil {
		t.Fatal("a sandbox holding no ruleset was taken under the gate")
	}
	if err := after.verifyMember(unprotected.GetId()); err == nil || !strings.Contains(err.Error(), "before this enforcer connected") {
		t.Fatalf("error = %v, want the pre-existing sandbox refusal", err)
	}
}

// Recovery verifies the live ruleset against the base plus the granted exits:
// with the grant the pod recovers, without it the held exits are refused.
func TestRecoverAPodHoldingExitsInTheNamespace(t *testing.T) {
	exits := []exit{{Range: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}}
	mesh := gateCtr("c8s-mesh", testMeshUID)
	meshLaunch := gatedContainer{role: meshRole, digest: digestOther, argv: []string{"/app/c8s", "armtls-mesh"}}

	pid := sandboxProcess(t)
	p := meshPod("default", "pod", sandboxNetNSPath(pid))
	p.Pid = pid
	before := newMeshGate(*meshRoles(), discardLogger())
	if err := before.protect(p); err != nil {
		t.Fatalf("protect: %v", err)
	}
	if err := extendPodRuleset(before.pods[p.GetId()].netns, before.policy, "default", exits); err != nil {
		t.Fatalf("extend the ruleset with the granted exit: %v", err)
	}
	ran := []recoveredContainer{{ctr: mesh, launch: meshLaunch, running: true}}

	granted := newMeshGate(*meshRoles(), discardLogger())
	if err := granted.recoverPod(p, ran, recoveredExits{entry: "collector", exits: exits}); err != nil {
		t.Fatalf("recover a pod holding its granted exit: %v", err)
	}
	if err := granted.verifyMember(p.GetId()); err != nil {
		t.Fatalf("a recovered pod holding its granted exit was refused an assertion: %v", err)
	}
	if held := granted.grantedExits(p.GetId()); !slices.Equal(held, exits) {
		t.Fatalf("recovered exits = %v, want %v", held, exits)
	}

	// No grant: the exit still live in the namespace is refused, naming the cause.
	ungranted := newMeshGate(*meshRoles(), discardLogger())
	err := ungranted.recoverPod(p, ran, recoveredExits{cause: errors.New("no served allowlist on this node yet")})
	if err == nil || !strings.Contains(err.Error(), "granted no exits") {
		t.Fatalf("error = %v, want a refusal naming the undecided cause", err)
	}
	if err := ungranted.verifyMember(p.GetId()); err == nil {
		t.Fatal("a pod refused on recovery was verified as a member")
	}

	// A base-only ruleset recovers with no grant.
	bpid := sandboxProcess(t)
	base := meshPod("default", "base", sandboxNetNSPath(bpid))
	base.Pid = bpid
	beforeBase := newMeshGate(*meshRoles(), discardLogger())
	if err := beforeBase.protect(base); err != nil {
		t.Fatalf("protect base pod: %v", err)
	}
	baseGate := newMeshGate(*meshRoles(), discardLogger())
	if err := baseGate.recoverPod(base, ran, recoveredExits{cause: errors.New("no served allowlist on this node yet")}); err != nil {
		t.Fatalf("a base-ruleset pod with an undecided grant was refused: %v", err)
	}
	if err := baseGate.verifyMember(base.GetId()); err != nil {
		t.Fatalf("a recovered base-ruleset pod was refused an assertion: %v", err)
	}
}

// A container's network namespace is matched to the sandbox's by kernel
// identity, not path; a different namespace is refused.
func TestRecoverMatchesTheSandboxNamespaceByIdentity(t *testing.T) {
	requireNetNS(t)
	// The test's own namespace, named two ways.
	proven, err := namespaceFile("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	state := &protectedPod{netns: proven, kubeNamespace: "default"}
	relabelled := fmt.Sprintf("/proc/%d/ns/net", os.Getpid())

	ctr := &api.Container{
		Name:  "app",
		Linux: &api.LinuxContainer{Namespaces: []*api.LinuxNamespace{{Type: "network", Path: relabelled}}},
	}
	if err := state.requireSandboxNetwork(ctr, true); err != nil {
		t.Fatalf("a running container reported the sandbox namespace under another path and was refused: %v", err)
	}

	// A stopped container is not checked.
	gone := &api.Container{
		Name:  "exited",
		Linux: &api.LinuxContainer{Namespaces: []*api.LinuxNamespace{{Type: "network", Path: "/proc/2147483647/ns/net"}}},
	}
	if err := state.requireSandboxNetwork(gone, false); err != nil {
		t.Fatalf("a stopped container's missing namespace handle was refused: %v", err)
	}

	// A running container whose /proc handle has since vanished has exited.
	if err := state.requireSandboxNetwork(gone, true); err != nil {
		t.Fatalf("a running container whose /proc handle is gone was refused: %v", err)
	}

	elsewhere := sandboxProcess(t)
	moved := &api.Container{
		Name:  "moved",
		Linux: &api.LinuxContainer{Namespaces: []*api.LinuxNamespace{{Type: "network", Path: sandboxNetNSPath(elsewhere)}}},
	}
	if err := state.requireSandboxNetwork(moved, true); err == nil {
		t.Fatal("a container in another network namespace was taken as the sandbox's")
	}
}

// waitForNamespaceGone waits for a killed sandbox's namespace handle to
// disappear, which the kernel does once the process is reaped.
func waitForNamespaceGone(path string) error {
	for range 100 {
		if _, err := namespaceFile(path); err != nil {
			return nil
		}
		unix.Nanosleep(&unix.Timespec{Nsec: 10_000_000}, nil)
	}
	return fmt.Errorf("%s is still a network namespace", path)
}
