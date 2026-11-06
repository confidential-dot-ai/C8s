package podstatus

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// The runtime starts after the policy is published, the manifest is written
// only once the plugin reports the assigned UID, and the kubelet starts last;
// an interruption at any boundary exposes no manifest to a kubelet, and the
// recovery completes the install and starts both units again, idempotently.
func TestAssignmentInstallStartsTheKubeletOnlyAfterThePluginRegisteredThePod(t *testing.T) {
	runtime := nodeservices.PodRuntime{UID: "pod", Policy: []byte("assigned policy"), Manifest: []byte("assigned manifest")}
	for _, boundary := range []string{"policy", "runtime", "health", "kubelet"} {
		t.Run(boundary, func(t *testing.T) {
			manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
			fail := errors.New("simulated interruption")
			var started []string
			registered, recovering := false, false
			start := func(_ context.Context, unit string) error {
				started = append(started, unit)
				data, err := policy.ReadFile("image-policy.yaml")
				if err != nil || !bytes.Equal(data, runtime.Policy) {
					t.Fatal("a unit started before the policy was published")
				}
				_, manifestErr := manifests.Stat("pod.yaml")
				switch unit {
				case podRuntimeUnit:
					if !recovering && !errors.Is(manifestErr, os.ErrNotExist) {
						t.Fatal("manifest appeared before the runtime started")
					}
					if boundary == "runtime" && !recovering {
						return fail
					}
				case podKubeletUnit:
					if !registered {
						t.Fatal("kubelet started before the plugin registered the pod")
					}
					if data, err := manifests.ReadFile("pod.yaml"); err != nil || !bytes.Equal(data, runtime.Manifest) {
						t.Fatal("kubelet started before the manifest was published")
					}
					if boundary == "kubelet" && !recovering {
						return fail
					}
				default:
					t.Fatalf("unknown unit %s", unit)
				}
				return nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			health := func(_ context.Context, uid string) error {
				if uid != runtime.UID {
					t.Fatal("wrong assignment health identity")
				}
				if !slices.Contains(started, podRuntimeUnit) {
					t.Fatal("health was polled before the runtime started")
				}
				if _, err := manifests.Stat("pod.yaml"); !recovering && !errors.Is(err, os.ErrNotExist) {
					t.Fatal("manifest published before the plugin registered the pod")
				}
				if boundary == "health" && !recovering {
					cancel()
					return fail
				}
				registered = true
				return nil
			}
			if boundary == "policy" {
				if err := policy.Mkdir("image-policy.yaml", 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := installAssignment(ctx, runtime, manifests, policy, start, health); err == nil {
				t.Fatal("interruption hidden")
			}
			cancel()
			if slices.Contains(started, podKubeletUnit) && boundary != "kubelet" {
				t.Fatal("interrupted install started the kubelet")
			}
			if boundary == "policy" {
				if err := policy.Remove("image-policy.yaml"); err != nil {
					t.Fatal(err)
				}
			}
			started, registered, recovering = nil, false, true
			if err := installAssignment(t.Context(), runtime, manifests, policy, start, health); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(started, []string{podRuntimeUnit, podKubeletUnit}) {
				t.Fatalf("recovery started %v", started)
			}
			// A completed install is recovered by starting the units again and
			// nothing else; a start is idempotent for a running unit.
			started = nil
			if err := installAssignment(t.Context(), runtime, manifests, policy, start, func(context.Context, string) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(started, []string{podRuntimeUnit, podKubeletUnit}) {
				t.Fatalf("published assignment started %v", started)
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
			forbidden := func(context.Context, string) error { t.Fatal("unsafe output reached runtime mutation"); return nil }
			if err := installAssignment(t.Context(), runtime, manifests, policy, forbidden, nil); err == nil {
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

// An install the boot can no longer complete is abandoned rather than retried:
// an installed output that differs from the assignment, or a plugin that
// ended the pod identity.
func TestAssignmentInstallAbandonsAMismatchOrAnEndedIdentity(t *testing.T) {
	runtime := nodeservices.PodRuntime{UID: "pod", Policy: []byte("policy"), Manifest: []byte("manifest")}
	for _, kind := range []string{"policy", "manifest", "ended"} {
		t.Run(kind, func(t *testing.T) {
			manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
			health := func(context.Context, string) error { return nil }
			switch kind {
			case "policy":
				if err := fileutil.WriteAtomicRoot(policy, "image-policy.yaml", []byte("other"), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := fileutil.WriteAtomicRoot(policy, "image-policy.yaml", runtime.Policy, 0600); err != nil {
					t.Fatal(err)
				}
				if err := fileutil.WriteAtomicRoot(manifests, "pod.yaml", []byte("other"), 0600); err != nil {
					t.Fatal(err)
				}
			case "ended":
				health = func(context.Context, string) error { return errPodIdentityEnded }
			}
			start := func(context.Context, string) error { return nil }
			err := installAssignment(t.Context(), runtime, manifests, policy, start, health)
			if !errors.Is(err, errAssignmentAbandoned) {
				t.Fatalf("install with %s = %v, want abandonment", kind, err)
			}
			if _, err := manifests.Stat("pod.yaml"); kind != "manifest" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("abandoned install published a manifest")
			}
		})
	}
	// A transient health failure is retried, not abandoned.
	manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
	calls := 0
	health := func(context.Context, string) error {
		calls++
		if calls == 1 {
			return errors.New("not registered yet")
		}
		return nil
	}
	if err := installAssignment(t.Context(), runtime, manifests, policy, func(context.Context, string) error { return nil }, health); err != nil || calls != 2 {
		t.Fatalf("transient failure: %v after %d polls", err, calls)
	}
}

// The plugin's registration is polled until it names the assigned UID; the
// runtime is started once, and the manifest waits for the registration.
func TestAssignmentInstallWaitsForThePluginWithoutStartingTheRuntimeAgain(t *testing.T) {
	manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
	runtime := nodeservices.PodRuntime{UID: "pod", Policy: []byte("policy"), Manifest: []byte("manifest")}
	healthCalls, runtimeStarts := 0, 0
	start := func(_ context.Context, unit string) error {
		if unit == podRuntimeUnit {
			runtimeStarts++
		}
		return nil
	}
	health := func(_ context.Context, uid string) error {
		healthCalls++
		if uid != runtime.UID {
			t.Fatal("wrong assignment health identity")
		}
		if _, err := manifests.Stat("pod.yaml"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("manifest published before the plugin registered the pod")
		}
		if healthCalls < 3 {
			return errors.New("admission not registered yet")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := installAssignment(ctx, runtime, manifests, policy, start, health); err != nil {
		t.Fatal(err)
	}
	if runtimeStarts != 1 || healthCalls != 3 {
		t.Fatalf("handoff calls: runtime starts=%d health=%d", runtimeStarts, healthCalls)
	}
	data, err := manifests.ReadFile("pod.yaml")
	if err != nil || !bytes.Equal(data, runtime.Manifest) {
		t.Fatalf("registered plugin did not publish assignment: %v", err)
	}
}
