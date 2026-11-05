package podstatus

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

func assignmentTestRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// The install is restartable at every boundary, the manifest is written
// last, and a published assignment is never reinstalled or its runtime restarted.
func TestAssignmentInstallCrashRecoveryAndManifestLast(t *testing.T) {
	runtime := nodeservices.PodRuntime{UID: "pod", Policy: []byte("assigned policy"), Manifest: []byte("assigned manifest")}
	for _, boundary := range []string{"empty", "policy", "restart", "health", "manifest"} {
		t.Run(boundary, func(t *testing.T) {
			manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
			fail := errors.New("simulated interruption")
			emptyCalls, restarts := 0, 0
			empty := func(context.Context) error {
				emptyCalls++
				if boundary == "empty" || boundary == "manifest" && emptyCalls == 2 {
					return fail
				}
				return nil
			}
			restart := func(context.Context) error {
				restarts++
				if _, err := manifests.Stat("pod.yaml"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("manifest appeared before restart")
				}
				data, err := policy.ReadFile("image-policy.yaml")
				if err != nil || !bytes.Equal(data, runtime.Policy) {
					t.Fatal("restart preceded policy publication")
				}
				if boundary == "restart" {
					return fail
				}
				return nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			health := func(context.Context, string) error {
				if boundary == "health" {
					cancel()
					return fail
				}
				return nil
			}
			if boundary == "policy" {
				if err := policy.Mkdir("image-policy.yaml", 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := installAssignment(ctx, runtime, manifests, policy, empty, restart, health); err == nil {
				t.Fatal("interruption hidden")
			}
			cancel()
			if _, err := manifests.Stat("pod.yaml"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("interrupted install exposed manifest")
			}
			if boundary == "policy" {
				if err := policy.Remove("image-policy.yaml"); err != nil {
					t.Fatal(err)
				}
			}
			if err := installAssignment(t.Context(), runtime, manifests, policy, func(context.Context) error { return nil }, func(context.Context) error { restarts++; return nil }, func(_ context.Context, uid string) error {
				if uid != "pod" {
					t.Fatal("wrong policy identity")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := restarts
			forbidden := func(context.Context) error { t.Fatal("published assignment restarted a running runtime"); return nil }
			if err := installAssignment(t.Context(), runtime, manifests, policy, forbidden, forbidden, func(context.Context, string) error { t.Fatal("published assignment awaited health"); return nil }); err != nil {
				t.Fatal(err)
			}
			if restarts != before {
				t.Fatal("recovery restarted the runtime")
			}
		})
	}
}

// An assigned manifest or floor is never replaced, and an
// output that is not a private regular file is refused before any mutation.
func TestAssignmentInstallRefusesReplacementAndUnsafeOutputs(t *testing.T) {
	for _, kind := range []string{"manifest", "policy", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
			runtime := nodeservices.PodRuntime{UID: "pod", Policy: []byte("policy"), Manifest: []byte("manifest")}
			if err := fileutil.WriteAtomicRoot(policy, "image-policy.yaml", runtime.Policy, 0600); err != nil {
				t.Fatal(err)
			}
			if err := fileutil.WriteAtomicRoot(manifests, "pod.yaml", runtime.Manifest, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "manifest":
				runtime.Manifest = []byte("replacement")
			case "policy":
				runtime.Policy = []byte("replacement")
			case "symlink":
				if err := manifests.Remove("pod.yaml"); err != nil {
					t.Fatal(err)
				}
				if err := manifests.Symlink(filepath.Join(policy.Name(), "image-policy.yaml"), "pod.yaml"); err != nil {
					t.Fatal(err)
				}
			}
			forbidden := func(context.Context) error { t.Fatal("unsafe output reached runtime mutation"); return nil }
			if err := installAssignment(t.Context(), runtime, manifests, policy, forbidden, forbidden, nil); err == nil {
				t.Fatal("assignment output changed or unsafe output accepted")
			}
		})
	}
}

// One service holds the store, a record is never replaced, and a record
// readable by others is refused.
func TestAssignmentStoreExclusiveAndImmutable(t *testing.T) {
	root := assignmentTestRoot(t)
	store, err := lockAssignmentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.lock.Close()
	if _, err := lockAssignmentStore(root); err == nil {
		t.Fatal("second service acquired assignment authority")
	}
	record := &assignmentRecord{Version: 1, Request: []byte("{}"), ServingKey: []byte("original")}
	if err := store.Commit(record); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(&assignmentRecord{Version: 2}); err == nil {
		t.Fatal("accepted record overwritten")
	}
	got, err := store.Load()
	if err != nil || got.Version != 1 || !bytes.Equal(got.ServingKey, record.ServingKey) {
		t.Fatalf("record lost: %v", err)
	}
	if err := root.Chmod(assignmentRecordName, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("public assignment record accepted")
	}
}

// Wait for the assigned UID with the runtime still empty, retrying
// unavailable observations without a second restart.
func TestAssignmentInstallWaitsForRuntimeObservationsWithoutRestartingAgain(t *testing.T) {
	manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
	runtime := nodeservices.PodRuntime{UID: "pod", Policy: []byte("policy"), Manifest: []byte("manifest")}
	emptyCalls, healthCalls, restarts := 0, 0, 0
	empty := func(context.Context) error {
		emptyCalls++
		if emptyCalls == 2 {
			return errors.Join(errAssignmentRuntimeUnavailable, errors.New("kubelet starting"))
		}
		return nil
	}
	health := func(_ context.Context, uid string) error {
		healthCalls++
		if uid != runtime.UID {
			t.Fatal("wrong assignment health identity")
		}
		if _, err := manifests.Stat("pod.yaml"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("manifest published before runtime observations")
		}
		if healthCalls == 2 {
			return errors.New("admission temporarily unregistered")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := installAssignment(ctx, runtime, manifests, policy, empty, func(context.Context) error { restarts++; return nil }, health); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 || emptyCalls != 3 || healthCalls != 3 {
		t.Fatalf("handoff calls: restarts=%d empty=%d health=%d", restarts, emptyCalls, healthCalls)
	}
	data, err := manifests.ReadFile("pod.yaml")
	if err != nil || !bytes.Equal(data, runtime.Manifest) {
		t.Fatalf("ready runtime did not publish assignment: %v", err)
	}
}
