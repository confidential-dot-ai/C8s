//go:build linux

package c8srunc

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func TestSharedPIDGrantInTheNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root and CAP_SYS_ADMIN")
	}
	if err := nriimagepolicy.InitializePIDNamespaceProof(); err != nil {
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
	containerID, sandboxID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	path, device, inode, err := nriimagepolicy.EnsurePIDNamespace(dir, sandboxID, uint32(sandbox.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nriimagepolicy.RemovePIDNamespace(dir, sandboxID) })
	grant := nriimagepolicy.PIDNamespaceGrant{ContainerID: containerID, SandboxID: sandboxID, PodUID: "uid", Policy: "policy", Path: path, Device: device, Inode: inode}
	if err := nriimagepolicy.WritePIDNamespaceGrant(dir, grant); err != nil {
		t.Fatal(err)
	}
	bundle := workloadBundle()
	bundle.Annotations[annotationSandboxID] = sandboxID
	bundle.Annotations[annotationSandboxUID] = "uid"
	for i := range bundle.Linux.Namespaces {
		if bundle.Linux.Namespaces[i].Type == specs.PIDNamespace {
			bundle.Linux.Namespaces[i].Path = path
		}
	}
	check := func() error { return requireFloorWithPIDGrant(bundle, containerID, nil, testFloor(), "", dir) }
	if err := check(); err != nil {
		t.Fatalf("refused the granted application: %v", err)
	}
	bundle.Annotations[annotationContainerName] = "c8s-mesh"
	if err := check(); err == nil {
		t.Fatal("allowed a support container to share the application namespace")
	}
	delete(bundle.Annotations, annotationContainerName)
	bundle.Annotations[annotationSandboxUID] = "other-uid"
	if err := check(); err == nil {
		t.Fatal("allowed a grant from another pod")
	}
	bundle.Annotations[annotationSandboxUID] = "uid"
	if err := nriimagepolicy.RemovePIDNamespaceGrant(dir, containerID); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("allowed a shared namespace without a runtime grant")
	}
}
