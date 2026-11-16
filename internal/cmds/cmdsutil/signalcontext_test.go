package cmdsutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const signalContextHelperEnv = "C8S_SIGNAL_CONTEXT_HELPER"

// The first SIGTERM cancels the context; a later one ends the process even
// though nothing is left waiting on that context.
func TestSignalContextCancelsOnTheFirstSignalAndDiesOnTheNext(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	helper := exec.CommandContext(ctx, executable, "-test.run=^TestSignalContextHelper$")
	helper.Env = append(os.Environ(), signalContextHelperEnv+"=1")
	out, err := helper.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("helper ended with %v, want death by signal", err)
	}
	status := exit.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("helper ended with %v, want death by SIGTERM", exit)
	}
	if !strings.Contains(string(out), "cancelled") {
		t.Fatalf("helper died before its context was cancelled; output %q", out)
	}
}

// TestSignalContextHelper is the process the test above signals.
func TestSignalContextHelper(t *testing.T) {
	if os.Getenv(signalContextHelperEnv) == "" {
		return
	}
	ctx, stop := SignalContext()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
	fmt.Println("cancelled")
	// Resent until the handler is gone and the default action ends the process.
	for {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
