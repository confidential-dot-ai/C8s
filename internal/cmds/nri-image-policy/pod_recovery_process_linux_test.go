//go:build linux

package nriimagepolicy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPodRecoveryProcessProofRefusesWrongContainerAndExitedPID(t *testing.T) {
	requireNetNS(t)
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		_ = child.Process.Kill()
		if !waited {
			_ = child.Wait()
		}
	})
	pid := uint32(child.Process.Pid)
	before, err := readPodProcessBirth(pid)
	if err != nil || before == 0 {
		t.Fatalf("live process birth: %d, %v", before, err)
	}
	again, err := readPodProcessBirth(pid)
	if err != nil || again != before {
		t.Fatalf("live process identity was unstable: %d, %v", again, err)
	}
	if _, err := readPodProcessIdentity(pid, strings.Repeat("f", 64)); err == nil {
		t.Fatal("live process claimed a different runtime container")
	}
	if _, err := readPodProcessIdentity(0, "missing"); err == nil {
		t.Fatal("absent process claimed a runtime container")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// Keep the zombie un-reaped so /proc/stat is still readable: a readable
	// birth time alone cannot authorize a process that has already exited.
	until := time.Now().Add(3 * time.Second)
	for {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			t.Fatal(err)
		}
		end := bytes.LastIndexByte(raw, ')')
		if end >= 0 && strings.HasPrefix(string(raw[end+1:]), " Z ") {
			break
		}
		if time.Now().After(until) {
			t.Fatal("killed fixture did not reach zombie state")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := readPodProcessBirth(pid); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("zombie retained process authority: %v", err)
	}
	if err := child.Wait(); err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatal(err)
		}
	}
	waited = true
	if _, err := readPodProcessBirth(pid); err == nil {
		t.Fatal("reaped PID retained process authority")
	}
}

// Use real kernel membership, including a nested scope named after another
// container. The nested name must not replace the original runtime identity.
func TestPodRecoveryProcessProofRetainsOutermostCgroupIdentity(t *testing.T) {
	requireNetNS(t)
	base, err := os.MkdirTemp("/sys/fs/cgroup", "c8s-pod-recovery-")
	if err != nil {
		if os.Getenv("C8S_REQUIRE_NFT") == "1" {
			t.Fatalf("required recovery cgroup test: %v", err)
		}
		t.Skipf("requires writable delegated cgroup v2: %v", err)
	}
	groups := []string{base}
	var child *exec.Cmd
	t.Cleanup(func() {
		if child != nil && child.Process != nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		for i := len(groups) - 1; i >= 0; i-- {
			if err := os.Remove(groups[i]); err != nil {
				t.Errorf("remove owned recovery cgroup: %v", err)
			}
		}
	})
	makeScope := func(parent string) (string, string) {
		t.Helper()
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		id := hex.EncodeToString(raw[:])
		path := filepath.Join(parent, "cri-containerd-"+id+".scope")
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		groups = append(groups, path)
		return id, path
	}
	id, scope := makeScope(base)
	nestedID, nestedScope := makeScope(scope)
	child = exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(child.Process.Pid)
	birth, err := readPodProcessBirth(pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{scope, nestedScope} {
		if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readPodProcessIdentity(pid, id)
		if err != nil || got != birth {
			t.Fatalf("original runtime cgroup lost its process identity: %d, %v", got, err)
		}
		if _, err := readPodProcessIdentity(pid, nestedID); err == nil {
			t.Fatal("nested container scope replaced the original runtime identity")
		}
	}
}
