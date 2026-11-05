//go:build linux

package nriimagepolicy

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The parent stays in the node namespace; only disposable child processes join.
func TestApplicationPIDSharingInTheNamespace(t *testing.T) {
	requireNetNS(t)
	for _, name := range []string{"nsenter", "unshare", "sh", "tr", "sleep", "kill"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	start := func(cmd *exec.Cmd) <-chan error {
		t.Helper()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait(); close(done) }()
		t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
		return done
	}
	sandbox := exec.CommandContext(ctx, "sleep", "600")
	sandbox.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}
	start(sandbox)
	support := exec.CommandContext(ctx, "sleep", "602")
	support.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}
	start(support)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sandboxID := strings.Repeat("d", 64)
	path, device, inode, err := EnsurePIDNamespace(dir, sandboxID, uint32(sandbox.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = RemovePIDNamespace(dir, sandboxID) })
	app := func(marker string) <-chan error {
		return start(exec.CommandContext(ctx, "nsenter", "--pid="+path, "--", "sleep", marker))
	}
	prefill, decode := app("601"), app("603")
	const scan = `for f in /proc/[0-9]*/cmdline; do p=${f%/cmdline}; printf '%s ' "${p##*/}"; tr '\000' ' ' < "$f"; printf '\n'; done`
	var prefillPID string
	visible := func() {
		t.Helper()
		for {
			out, err := exec.CommandContext(ctx, "nsenter", "--pid="+path, "--", "unshare", "--mount", "--mount-proc", "sh", "-c", scan).CombinedOutput()
			if err != nil {
				t.Fatalf("read the application procfs: %v: %s", err, out)
			}
			found := map[string]string{}
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 3 && fields[1] == "sleep" {
					found[fields[2]] = fields[0]
				}
			}
			if found["602"] != "" {
				t.Fatal("the application can see the support process")
			}
			if found["601"] != "" && found["603"] != "" {
				prefillPID = found["601"]
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("the workers did not become visible to each other")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	visible()
	if out, err := exec.CommandContext(ctx, "nsenter", "--pid="+path, "--", "kill", "-KILL", prefillPID).CombinedOutput(); err != nil {
		t.Fatalf("stop prefill: %v: %s", err, out)
	}
	<-prefill
	prefill = app("601")
	visible()
	if gotDevice, gotInode, err := PIDNamespaceIdentity(path); err != nil || gotDevice != device || gotInode != inode {
		t.Fatal("a worker restart changed the shared namespace")
	}
	_ = sandbox.Process.Kill()
	for _, done := range []<-chan error{prefill, decode} {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("a worker survived the sandbox's PID 1")
		}
	}
	if err := support.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("sandbox shutdown killed the isolated support process: %v", err)
	}
}
