//go:build linux

package nriimagepolicy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
)

// requireNetNS fails rather than skips when C8S_REQUIRE_NFT is set, which is
// how CI runs these tests: a namespace it cannot create must not leave the
// enforcer's install and verify paths silently untested. Verification walks
// BPF link ids, which needs CAP_BPF in the initial user namespace, so uid 0 in
// a user namespace of its own is not enough — the enforcer runs as the node's
// own root.
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
	err = verifyPodRuleset(replaced, *meshRoles())
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
	gate := newMeshGate(meshRoles(), discardLogger())

	if err := gate.protect(pod); err != nil {
		t.Fatalf("protect: %v", err)
	}
	mesh := &api.Container{
		Name: "c8s-mesh",
		User: &api.User{Uid: testMeshUID},
	}
	if err := gate.admit(pod, mesh, gatedContainer{role: meshRole}); err != nil {
		t.Fatalf("the mesh endpoint was refused in a protected pod: %v", err)
	}
	workload := &api.Container{
		Name: "app",
		User: &api.User{Uid: testWorkloadUID},
	}
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
	later := &api.Container{
		Name: "sidecar",
		User: &api.User{Uid: testWorkloadUID},
	}
	if err := gate.admit(pod, later, gatedContainer{}); err != nil {
		t.Fatalf("a container joining a pod that holds an identity was refused: %v", err)
	}
	role := &api.Container{
		Name: "c8s-cert",
		User: &api.User{Uid: testCertUID},
	}
	if err := gate.admit(pod, role, gatedContainer{role: testCertRole}); err == nil {
		t.Fatal("a platform role joined a pod behind its workload")
	}

	// A second install into the same namespace is refused, so the pod's
	// protection cannot be replaced under a running container.
	if err := installPodRuleset(podNamespace{path: sandboxNetNSPath(pid)}, *gate.policy); !errors.Is(err, ruleset.ErrForeignRules) {
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
