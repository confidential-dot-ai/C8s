//go:build linux

package nriimagepolicy

// The enforcer's notion of its own network namespace has to survive a thread
// of it attaching to a pod's. Installing a pod ruleset attaches the thread it
// runs on and never detaches it, and the Go runtime parks the process's
// leader thread rather than destroying it, so selfNetworkNamespace, which
// names the leader thread's namespace, can come to name a pod's. No test
// goroutine reliably runs on the leader thread, so the probe runs as a test
// process of its own, where TestMain holds that thread.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// leaderThreadSandboxEnv carries the sandbox process whose network namespace
// a probe process attaches its leader thread to.
const leaderThreadSandboxEnv = "C8S_LEADER_THREAD_SANDBOX"

// leaderThreadSandbox is that sandbox process, and empty in an ordinary test
// process.
var leaderThreadSandbox = os.Getenv(leaderThreadSandboxEnv)

// Locking the thread during package initialisation is what keeps main.main,
// and so TestMain, on the leader thread.
func init() {
	if leaderThreadSandbox != "" {
		runtime.LockOSThread()
	}
}

func TestMain(m *testing.M) {
	if leaderThreadSandbox == "" {
		os.Exit(m.Run())
	}
	if err := proveWithTheLeaderThreadAttached(leaderThreadSandbox); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// A sandbox namespace a thread of the enforcer sits in is still that
// sandbox's: the namespace sandboxes are proven against is the one the
// enforcer read before any of its threads attached.
func TestProveWithTheLeaderThreadAttachedInTheNamespace(t *testing.T) {
	pid := sandboxProcess(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := exec.Command(binary)
	probe.Env = append(os.Environ(), fmt.Sprintf("%s=%d", leaderThreadSandboxEnv, pid))
	if out, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("the probe refused the namespace its leader thread sits in: %v\n%s", err, out)
	}
}

// proveWithTheLeaderThreadAttached is the whole of a probe process: it reads
// the enforcer's own network namespace, moves the leader thread into the
// sandbox's, and proves that namespace from there.
func proveWithTheLeaderThreadAttached(sandbox string) error {
	pid, err := strconv.ParseUint(sandbox, 10, 32)
	if err != nil {
		return fmt.Errorf("read the sandbox process id from %s: %w", leaderThreadSandboxEnv, err)
	}
	enforcer, err := enforcerNetworkNamespace()
	if err != nil {
		return err
	}
	if err := requireLeaderThread(); err != nil {
		return err
	}
	path := sandboxNetNSPath(uint32(pid))
	if err := enterNetNS(path); err != nil {
		return err
	}
	self, err := requireSelfNetNSIs(path)
	if err != nil {
		return err
	}
	if enforcer.id == self.id {
		return errors.New("the enforcer's own network namespace was read after the attachment")
	}
	if _, err := proveSandboxNamespace(path, uint32(pid)); err != nil {
		return fmt.Errorf("prove the sandbox namespace: %w", err)
	}
	return nil
}

// requireLeaderThread requires the calling thread to be the one
// selfNetworkNamespace names.
func requireLeaderThread() error {
	if tid := unix.Gettid(); tid != os.Getpid() {
		return fmt.Errorf("the probe runs on thread %d, not the process's leader %d", tid, os.Getpid())
	}
	return nil
}

// enterNetNS attaches the calling thread to the network namespace at path.
func enterNetNS(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer unix.Close(fd)
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter %s: %w", path, err)
	}
	return nil
}

// requireSelfNetNSIs requires selfNetworkNamespace to name the namespace at
// path, and answers with what it read there.
func requireSelfNetNSIs(path string) (podNamespace, error) {
	self, err := namespaceFile(selfNetworkNamespace)
	if err != nil {
		return podNamespace{}, err
	}
	attached, err := namespaceFile(path)
	if err != nil {
		return podNamespace{}, err
	}
	if self.id != attached.id {
		return podNamespace{}, fmt.Errorf("%s does not name the namespace at %s", selfNetworkNamespace, path)
	}
	return self, nil
}
