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

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func recoveryStoreFixture(t *testing.T) (*config, *podRecoveryStore, *podRecoveryState) {
	t.Helper()
	requireNetNS(t)
	ram := filepath.Join(t.TempDir(), "journal")
	mountPodTestRAM(t, ram)
	cfg := &config{Pod: &podConfig{UID: "one-assigned-pod", Generic: true}, WorkloadClaims: workloadClaimsConfig{SocketDir: ram}}
	store, err := openPodRecovery(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	state := &podRecoveryState{Version: 1, KernelBootID: store.kernelBootID, ConfigDigest: store.configDigest, BootID: strings.Repeat("b", 64), Processes: map[string]podRecoveredProcess{}, Histories: map[string]json.RawMessage{}, Containers: map[string]podRecoveredContainer{}, Denials: map[string]podRecoveredDenial{}, Sandboxes: []string{}, Mesh: map[string]podRecoveredMesh{}}
	if err := store.begin(); err != nil {
		t.Fatal(err)
	}
	if err := store.commit(state); err != nil {
		t.Fatal(err)
	}
	return cfg, store, state
}

func requireRecoveryRefusal(t *testing.T, cfg *config, want string) {
	t.Helper()
	recovered, err := openPodRecovery(cfg)
	if recovered != nil {
		_ = recovered.Close()
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("recovery error = %v, want %q", err, want)
	}
}

func TestPodRecoveryStoreSingleWriterAndInterruptedOwner(t *testing.T) {
	cfg, owner, state := recoveryStoreFixture(t)
	requireRecoveryRefusal(t, cfg, "writer already active")
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	successor, err := openPodRecovery(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	if successor.state.BootID != state.BootID || successor.state.ConfigDigest != state.ConfigDigest {
		t.Fatal("reopen changed the retained identity")
	}
	if err := successor.begin(); err != nil {
		t.Fatal(err)
	}
	if err := successor.begin(); err == nil {
		t.Fatal("a second transition entered before the first committed")
	}
	requireRecoveryRefusal(t, cfg, "writer already active")
	if err := successor.Close(); err != nil {
		t.Fatal(err)
	}
	// Releasing a dead writer's flock must not erase its uncommitted mutation.
	requireRecoveryRefusal(t, cfg, "interrupted transition")
}

func TestPodRecoveryStoreRejectsUntrustedDirectory(t *testing.T) {
	requireNetNS(t)
	for _, condition := range []string{"public", "foreign-owner", "symlink"} {
		t.Run(condition, func(t *testing.T) {
			ram := filepath.Join(t.TempDir(), "journal")
			mountPodTestRAM(t, ram)
			dir := filepath.Join(ram, podRecoveryDirectory)
			if condition == "symlink" {
				target := filepath.Join(ram, "elsewhere")
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, dir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if condition == "public" {
					if err := os.Chmod(dir, 0755); err != nil {
						t.Fatal(err)
					}
				}
				if condition == "foreign-owner" {
					if err := os.Chown(dir, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
			}
			cfg := &config{Pod: &podConfig{UID: "assigned"}, WorkloadClaims: workloadClaimsConfig{SocketDir: ram}}
			requireRecoveryRefusal(t, cfg, "recovery directory")
			if _, err := os.Lstat(filepath.Join(dir, "service.lock")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("untrusted directory acquired an authority lock")
			}
		})
	}
	t.Run("disk", func(t *testing.T) {
		dir, err := os.MkdirTemp("/var/tmp", "pod-recovery-disk-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		var fs unix.Statfs_t
		if err := unix.Statfs(dir, &fs); err != nil {
			t.Fatal(err)
		}
		if fs.Type == unix.TMPFS_MAGIC || fs.Type == unix.RAMFS_MAGIC {
			t.Skip("this runner's /var/tmp is also RAM-backed")
		}
		cfg := &config{Pod: &podConfig{UID: "assigned"}, WorkloadClaims: workloadClaimsConfig{SocketDir: dir}}
		requireRecoveryRefusal(t, cfg, "RAM")
	})
}

func TestPodRecoveryStoreRejectsDamagedRetainedAuthority(t *testing.T) {
	for _, condition := range []string{"unknown-field", "duplicate-field", "wrong-boot", "missing-map", "lost-boot-id", "terminal", "foreign-owner", "symlink", "oversized", "journal-without-state"} {
		t.Run(condition, func(t *testing.T) {
			cfg, store, state := recoveryStoreFixture(t)
			path := filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile)
			raw, err := store.root.ReadFile(podRecoveryStateFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			want := ""
			switch condition {
			case "unknown-field":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
				want = "unknown field"
			case "duplicate-field":
				raw = append([]byte(`{"version":1,`), raw[1:]...)
				want = "invalid Pod recovery JSON"
			case "wrong-boot":
				state.KernelBootID = "00000000-0000-0000-0000-000000000000"
				want = "identity or complete state"
			case "missing-map":
				state.Histories = nil
				want = "identity or complete state"
			case "lost-boot-id":
				state.BootID = "lost"
				want = "original boot identity"
			case "terminal":
				state.Terminal = "admission protection was lost"
				want = "previously ended"
			case "foreign-owner":
				if err := os.Chown(path, 65534, 65534); err != nil {
					t.Fatal(err)
				}
				want = "private root-owned regular"
			case "symlink":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".retained", path); err != nil {
					t.Fatal(err)
				}
				want = "private root-owned regular"
			case "oversized":
				if err := os.Truncate(path, maxPodRecoveryBytes+1); err != nil {
					t.Fatal(err)
				}
				want = "oversized"
			case "journal-without-state":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal), []byte(pushDigestA+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				want = "measured admission history"
			}
			switch condition {
			case "wrong-boot", "missing-map", "lost-boot-id", "terminal":
				raw, err = json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				fallthrough
			case "unknown-field", "duplicate-field":
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			requireRecoveryRefusal(t, cfg, want)
		})
	}
}

func TestPodRecoveryStoreFailedCommitCannotAdvertiseOldStateAsClean(t *testing.T) {
	cfg, store, state := recoveryStoreFixture(t)
	before, err := store.root.ReadFile(podRecoveryStateFile)
	if err != nil {
		t.Fatal(err)
	}
	replacement := *state
	replacement.Revision = 1
	if err := store.commit(&replacement); err == nil {
		t.Fatal("state changed without first fencing the transition")
	}
	if err := store.begin(); err != nil {
		t.Fatal(err)
	}
	// A real filesystem failure after the fence models loss of writable guest
	// storage; the old complete bytes must survive without becoming resumable.
	readOnlyRecoveryRoot(t, cfg, store)
	if err := store.commit(&replacement); !errors.Is(err, unix.EROFS) {
		t.Fatalf("read-only checkpoint did not surface its storage failure: %v", err)
	}
	after, err := store.root.ReadFile(podRecoveryStateFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed commit changed the last complete checkpoint: %v", err)
	}
	if _, err := store.root.Stat(podRecoveryPendingFile); err != nil {
		t.Fatal("failed commit lost its interruption fence")
	}
	if err := store.begin(); err == nil {
		t.Fatal("failed writer accepted another transition")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	requireRecoveryRefusal(t, cfg, "interrupted transition")
}

// If storage cannot create a fence or preserve a refusal by rename, continuing
// this guest would let a later restart recover the stale clean checkpoint.
func TestPodRecoveryStoreUnwritableRefusalRequiresGuestShutdown(t *testing.T) {
	cfg, store, _ := recoveryStoreFixture(t)
	readOnlyRecoveryRoot(t, cfg, store)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fatal := &fatalRecorder{}
	p := &plugin{cfg: cfg, recovery: store, podStarts: map[string]podStartGrant{"old": {}}, podBroker: &podCredentialBroker{ctx: ctx, cancel: cancel}, boot: &bootGate{logger: discardLogger(), powerOff: fatal.powerOff, exit: fatal.exit}}
	p.podMu.Lock()
	err := p.beginPodTransition()
	p.podMu.Unlock()
	if !errors.Is(err, unix.EROFS) || fatal.powerOffs != 1 || len(fatal.exits) != 1 || fatal.exits[0] != 1 {
		t.Fatalf("unrecordable refusal did not require guest shutdown: %v %+v", err, fatal)
	}
	if ctx.Err() == nil || len(p.podStarts) != 0 {
		t.Fatal("unrecordable refusal retained ephemeral authority")
	}
}

// A separate read-only mount lets the lock remain held on its original mount.
// Remounting that original mount is forbidden while its writable lock FD is
// open. The alias has the same inode and bytes and supplies real EROFS errors.
func readOnlyRecoveryRoot(t *testing.T, cfg *config, store *podRecoveryStore) {
	t.Helper()
	alias := t.TempDir()
	source := filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory)
	if err := unix.Mount(source, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(alias, 0); err != nil {
			t.Error(err)
		}
	})
	if err := unix.Mount("", alias, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(alias)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	before, err := store.root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	after, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("readonly fault changed recovery identity")
	}
	if err := store.root.Close(); err != nil {
		t.Fatal(err)
	}
	store.root = root
	requireRecoveryRefusal(t, cfg, "writer already active")
}
