//go:build linux

package nriimagepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPIDNamespaceProofRejectsUntrustedTargets(t *testing.T) {
	ordinary := filepath.Join(t.TempDir(), "ordinary")
	if err := os.WriteFile(ordinary, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/proc/self/ns/pid", "/proc/self/ns/net", ordinary, ordinary + ".missing"} {
		if _, _, err := ProvePIDNamespace(path, uint32(os.Getpid())); err == nil {
			t.Fatalf("proved %s as an isolated sandbox PID namespace", path)
		}
	}
	if _, _, err := ProvePIDNamespace("/proc/self/ns/pid", 0); err == nil {
		t.Fatal("proved a sandbox with no process")
	}
}

func TestPIDNamespaceGrantFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	container, sandbox := strings.Repeat("a", 64), strings.Repeat("b", 64)
	grant := PIDNamespaceGrant{ContainerID: container, SandboxID: sandbox, PodUID: "pod-uid", Policy: "policy", Path: filepath.Join(dir, "namespaces", sandbox)}
	if err := WritePIDNamespaceGrant(dir, grant); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPIDNamespaceGrant(dir, container)
	if err != nil || got == nil || *got != grant {
		t.Fatalf("read grant = %v, %v", got, err)
	}
	grant.Path = "/proc/self/ns/pid"
	if err := WritePIDNamespaceGrant(dir, grant); err == nil {
		t.Fatal("accepted a grant outside the pinned namespace directory")
	}
	if err := os.Chmod(filepath.Join(dir, container), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPIDNamespaceGrant(dir, container); err == nil {
		t.Fatal("accepted a writable grant")
	}
	if err := RemovePIDNamespaceGrant(dir, container); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPIDNamespaceGrant(dir, container); err != nil || got != nil {
		t.Fatalf("removed grant = %v, %v", got, err)
	}
	if _, err := ReadPIDNamespaceGrant(dir, "../escape"); err == nil {
		t.Fatal("accepted a non-runtime container ID")
	}
	grant.Path = filepath.Join(dir, "namespaces", sandbox)
	grant.ContainerID, grant.Policy = strings.Repeat("c", 64), "another-policy"
	if err := WritePIDNamespaceGrant(dir, grant); err == nil {
		t.Fatal("rebound a sandbox after its container grant was removed")
	}
	grant.Policy = "policy"
	if err := WritePIDNamespaceGrant(dir, grant); err != nil {
		t.Fatalf("refused the same group after container removal: %v", err)
	}
}

func TestPIDNamespacePinsInTheNamespace(t *testing.T) {
	requireNetNS(t)
	if err := InitializePIDNamespaceProof(); err != nil {
		t.Fatal(err)
	}
	sandbox := exec.Command("sleep", "600")
	sandbox.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}
	if err := sandbox.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sandbox.Process.Kill(); _ = sandbox.Wait() })
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sandboxID, containerID := strings.Repeat("b", 64), strings.Repeat("c", 64)
	path, device, inode, err := EnsurePIDNamespace(dir, sandboxID, uint32(sandbox.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := RemovePIDNamespace(dir, sandboxID); err != nil {
			t.Error(err)
		}
	})
	grant := PIDNamespaceGrant{ContainerID: containerID, SandboxID: sandboxID, PodUID: "pod-uid", Policy: "policy", Path: path, Device: device, Inode: inode}
	if err := WritePIDNamespaceGrant(dir, grant); err != nil {
		t.Fatal(err)
	}
	if err := CheckPIDNamespaceGrant(dir, containerID, sandboxID, "pod-uid", path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := EnsurePIDNamespace(dir, sandboxID, uint32(os.Getpid())); err == nil {
		t.Fatal("replaced an existing pin with the node namespace")
	}
	if err := CheckPIDNamespaceGrant(dir, containerID, sandboxID, "other-pod", path); err == nil {
		t.Fatal("accepted another pod UID")
	}
	grant.Inode++
	if err := WritePIDNamespaceGrant(dir, grant); err == nil {
		t.Fatal("rebound a sandbox to a different namespace identity")
	}
}
