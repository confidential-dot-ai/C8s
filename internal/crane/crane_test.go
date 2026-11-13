package crane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/crane/cranetest"
)

func TestDigest(t *testing.T) {
	cranetest.Install(t)
	got, err := Digest(context.Background(), "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != cranetest.DigA {
		t.Fatalf("Digest = %q, want %q", got, cranetest.DigA)
	}
	if _, err := Digest(context.Background(), "registry.example.com/unresolvable:v1"); err == nil {
		t.Fatal("expected a resolve failure")
	}
}

func TestConfig(t *testing.T) {
	cranetest.Install(t)
	cfg, err := Config(context.Background(), "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != "/bin/app" {
		t.Fatalf("entrypoint = %v", cfg.Config.Entrypoint)
	}
	if len(cfg.Config.Cmd) != 2 || cfg.Config.Cmd[0] != "serve" || cfg.Config.Cmd[1] != "--port=1" {
		t.Fatalf("cmd = %v", cfg.Config.Cmd)
	}
	if _, err := Config(context.Background(), "registry.example.com/badjson:v1"); err == nil || !strings.Contains(err.Error(), "parse crane config") {
		t.Fatalf("expected a config parse error, got %v", err)
	}
}

func TestManifestExists(t *testing.T) {
	cranetest.Install(t)
	if err := ManifestExists(context.Background(), "registry.example.com/app@"+cranetest.DigA); err != nil {
		t.Fatalf("existing manifest must not error: %v", err)
	}
	if err := ManifestExists(context.Background(), "registry.example.com/app@"+cranetest.DigB); err == nil {
		t.Fatal("expected a missing manifest to error")
	}
}

// installHangingCrane puts a crane stub on PATH that accepts the invocation
// and never answers — a registry that holds the connection open.
func installHangingCrane(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	// exec replaces the shell, so the deadline's kill has a single process to
	// signal and no child is left holding stdout.
	if err := os.WriteFile(filepath.Join(dir, "crane"), []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatalf("write crane stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestBoundsAHungRegistry pins the package's own deadline: `c8s allowlist lint
// --online` reaches crane with a context that carries none, so without this a
// stalled registry blocks the gate for the whole run.
func TestBoundsAHungRegistry(t *testing.T) {
	installHangingCrane(t)
	restore := commandTimeout
	commandTimeout = 200 * time.Millisecond
	t.Cleanup(func() { commandTimeout = restore })

	done := make(chan error, 1)
	go func() { done <- ManifestExists(context.Background(), "registry.example.com/app@"+cranetest.DigA) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ManifestExists error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("ManifestExists did not return within its timeout")
	}
}

// TestReturnsOnContextCancel pins that the caller's cancellation still wins
// when it fires before commandTimeout.
func TestReturnsOnContextCancel(t *testing.T) {
	installHangingCrane(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := Digest(ctx, "registry.example.com/app:v1"); done <- err }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Digest error = %v, want context.Canceled", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Digest did not return after context cancel")
	}
}
