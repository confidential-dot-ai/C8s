package probefile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbePassesOnNonEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := probe(path); err != nil {
		t.Fatalf("probe(non-empty file) = %v, want nil", err)
	}
}

func TestProbeFailsOnMissingFile(t *testing.T) {
	if err := probe(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("probe(missing) = nil, want error")
	}
}

func TestProbeFailsOnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}

	err := probe(path)
	if err == nil {
		t.Fatal("probe(empty) = nil, want error")
	}
}

func TestProbeFailsOnDirectory(t *testing.T) {
	if err := probe(t.TempDir()); err == nil {
		t.Fatal("probe(dir) = nil, want error")
	}
}

func TestWaitForReturnsOnceFileAppears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	go func() {
		time.Sleep(50 * time.Millisecond)
		tmp := filepath.Join(dir, "cert.pem.tmp")
		if err := os.WriteFile(tmp, []byte("hello"), 0600); err != nil {
			return
		}
		_ = os.Rename(tmp, path)
	}()

	// interval <= 0 exercises the default-interval branch; it is clamped to
	// 1s, so the file written above is seen on the second iteration.
	if err := waitFor(t.Context(), path, 0, 10*time.Second); err != nil {
		t.Fatalf("waitFor(appearing file) = %v, want nil", err)
	}
}

func TestWaitForTimesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never.pem")

	err := waitFor(t.Context(), path, 10*time.Millisecond, 50*time.Millisecond)
	if err == nil {
		t.Fatal("waitFor(missing, timeout) = nil, want error")
	}
}

// A non-positive interval is clamped to the 1s default, so even with a tiny
// timeout the call sleeps a full interval before giving up: it cannot return
// almost immediately in a busy spin.
func TestWaitForClampsNonPositiveInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never.pem")
	start := time.Now()
	if err := waitFor(t.Context(), path, 0, 50*time.Millisecond); err == nil {
		t.Fatal("waitFor(missing, timeout) = nil, want error")
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("waitFor returned after %v; the clamped 1s interval must sleep at least once", elapsed)
	}
}

// timeout 0 waits forever: waitFor must not give up on its own, and must
// return once the file appears.
func TestWaitForZeroTimeoutWaitsForFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	done := make(chan error, 1)
	go func() { done <- waitFor(t.Context(), path, 10*time.Millisecond, 0) }()

	select {
	case err := <-done:
		t.Fatalf("waitFor returned early with timeout 0: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	tmp := filepath.Join(dir, "cert.pem.tmp")
	if err := os.WriteFile(tmp, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitFor(appeared file) = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waitFor did not return after the file appeared")
	}
}

// A pod deleted while its gate waits stops the wait: the container exits
// without waiting for the file or the kubelet's SIGKILL.
func TestWaitForStopsWhenCancelled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never.pem")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- waitFor(ctx, path, 10*time.Millisecond, 0) }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waitFor(cancelled) = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waitFor did not return after its context was cancelled")
	}
}

func TestCmdOneShot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(non-empty file) = %v, want nil", err)
	}
}

func TestCmdWaitTimesOut(t *testing.T) {
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--wait",
		"--poll-interval", "10ms",
		"--timeout", "50ms",
		filepath.Join(t.TempDir(), "never.pem"),
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute(--wait, missing, timeout) = nil, want error")
	}
}
