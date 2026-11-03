//go:build linux

package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An empty but terminal guest must never look like a fresh generic assignment
// after a failed fence. Renaming the old checkpoint preserves a durable refusal
// even when allocating a new marker has already failed.
func TestPodRecoveryTerminalFenceFailureRetainsRefusalBeforeExecution(t *testing.T) {
	requireNetNS(t)
	ram := filepath.Join(t.TempDir(), "journal")
	mountPodTestRAM(t, ram)
	cfg := &config{Pod: &podConfig{UID: "assigned-before-execution", Generic: true}, WorkloadClaims: workloadClaimsConfig{SocketDir: ram}}
	store, err := openPodRecovery(cfg)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = store.Close()
		}
	})
	state := &podRecoveryState{Version: 1, KernelBootID: store.kernelBootID, ConfigDigest: store.configDigest, BootID: strings.Repeat("a", 64), Processes: map[string]podRecoveredProcess{}, Histories: map[string]json.RawMessage{}, Containers: map[string]podRecoveredContainer{}, Denials: map[string]podRecoveredDenial{}, Sandboxes: []string{}, Mesh: map[string]podRecoveredMesh{}}
	if err := store.begin(); err != nil {
		t.Fatal(err)
	}
	if err := store.commit(state); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := store.root.ReadFile(podRecoveryStateFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ram, podBrokerMarker)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture unexpectedly claimed a measured endpoint")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p := &plugin{cfg: cfg, recovery: store, podStarts: map[string]podStartGrant{"pending-start": {}}, podBroker: &podCredentialBroker{ctx: ctx, cancel: cancel}, boot: &bootGate{logger: discardLogger(), powerOff: func() error { t.Fatal("rename fallback unexpectedly powered off"); return nil }, exit: func(int) { t.Fatal("rename fallback unexpectedly exited") }}}
	store.failed = errors.New("prior marker allocation failure")
	reason := errors.New("terminal pre-execution state")
	p.podMu.Lock()
	p.endPodIdentity(reason)
	p.podMu.Unlock()
	if len(p.podStarts) != 0 || ctx.Err() == nil || !errors.Is(p.podBroker.terminal, reason) {
		t.Fatal("terminal fallback retained transient start or credential authority")
	}
	if _, err := store.root.Stat(podRecoveryStateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clean checkpoint survived terminal transition: %v", err)
	}
	fence, err := store.root.ReadFile(podRecoveryPendingFile)
	if err != nil || !bytes.Equal(fence, checkpoint) {
		t.Fatalf("terminal fallback did not rename the exact checkpoint: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	restarted, err := openPodRecovery(cfg)
	if restarted != nil {
		_ = restarted.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "interrupted transition") {
		t.Fatalf("terminal empty guest was eligible for a fresh assignment: %v", err)
	}
}
