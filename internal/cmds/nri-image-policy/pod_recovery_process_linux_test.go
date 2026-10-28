//go:build linux

package nriimagepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
