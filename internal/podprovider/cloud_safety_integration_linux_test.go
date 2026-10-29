//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func cloudOwnershipFixture(t *testing.T) (*cloudRun, *cloudOwned, cloudReceipt) {
	t.Helper()
	r := &cloudRun{dir: t.TempDir(), cfg: cloudRunConfig{Image: "c8s-pod@2026.10.27-1", CDSImage: "c8s-pod-cds@2026.10.27-1", Size: "s1.2x", Location: "us-west-1", DiskDigest: "sha256:" + strings.Repeat("a", 64), ManifestDigest: "sha256:" + strings.Repeat("b", 64)}}
	r.ledger = cloudLedger{Version: 1, Run: "pcvm-" + strings.Repeat("1", 24), Before: map[string]cloudReceipt{}, Owned: map[string]*cloudOwned{}}
	o := &cloudOwned{Key: "podcvm-owned", UID: "assigned-uid", Image: r.cfg.Image, LaunchKey: "public-key-only", Labels: map[string]string{"podcvm-provider": r.ledger.Run, "podcvm-uid": "owned"}, IntentAt: time.Now().UTC(), Attempted: true}
	in := cloudReceipt{ID: "i-owned", Name: o.Key, CreatedAt: o.IntentAt, Tee: "tdx", Size: r.cfg.Size, Location: r.cfg.Location, Labels: o.Labels}
	in.Image.Family = "c8s-pod"
	in.Image.Version = "2026.10.27-1"
	in.Image.Launch = "c8s-pod/1"
	in.Image.Digest = r.cfg.DiskDigest
	in.Attestation.ReferenceManifest.Digest = r.cfg.ManifestDigest
	in.Attestation.LaunchBinding.SHA256 = cloudHash([]byte(o.LaunchKey))
	r.ledger.Owned["a"] = o
	return r, o, in
}

func TestCloudAcceptanceOwnershipRefusesEveryChangedAuthority(t *testing.T) {
	mutations := map[string]func(*cloudRun, *cloudOwned, *cloudReceipt){
		"baseline": func(r *cloudRun, _ *cloudOwned, in *cloudReceipt) { r.ledger.Before[in.ID] = *in },
		"launch-key": func(_ *cloudRun, _ *cloudOwned, in *cloudReceipt) {
			in.Attestation.LaunchBinding.SHA256 = strings.Repeat("0", 64)
		},
		"image":    func(_ *cloudRun, _ *cloudOwned, in *cloudReceipt) { in.Image.Version = "2026.10.24-1" },
		"contract": func(_ *cloudRun, _ *cloudOwned, in *cloudReceipt) { in.Image.Launch = "c8s-node/1" },
		"manifest": func(_ *cloudRun, _ *cloudOwned, in *cloudReceipt) {
			in.Attestation.ReferenceManifest.Digest = "sha256:" + strings.Repeat("0", 64)
		},
		"disk": func(_ *cloudRun, _ *cloudOwned, in *cloudReceipt) {
			in.Image.Digest = "sha256:" + strings.Repeat("0", 64)
		},
		"labels": func(_ *cloudRun, _ *cloudOwned, in *cloudReceipt) {
			in.Labels = map[string]string{"podcvm-provider": "foreign"}
		},
		"creation": func(_ *cloudRun, o *cloudOwned, in *cloudReceipt) { in.CreatedAt = o.IntentAt.Add(-time.Hour) },
		"shape":    func(_ *cloudRun, _ *cloudOwned, in *cloudReceipt) { in.Size = "foreign" },
		"receipt": func(_ *cloudRun, o *cloudOwned, in *cloudReceipt) {
			prior := *in
			prior.ID = "i-another"
			o.Receipt = &prior
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r, o, in := cloudOwnershipFixture(t)
			if err := r.checkOwned(o, in); err != nil {
				t.Fatal(err)
			}
			mutate(r, o, &in)
			if err := r.checkOwned(o, in); err == nil {
				t.Fatal("changed ownership authority accepted")
			}
		})
	}
}

func TestCloudAcceptanceBootStopsOnLostOrTerminalPod(t *testing.T) {
	for _, scenario := range []string{"missing", "replaced", "deleting", "preempted", "failed", "succeeded", "foreign-node", "delete-requested", "deleted-record", "terminal-record"} {
		t.Run(scenario, func(t *testing.T) {
			original := fixturePod()
			original.Name = "cloud-a"
			pod := original.DeepCopy()
			switch scenario {
			case "replaced":
				pod.UID = "replacement-uid"
			case "deleting":
				pod.DeletionTimestamp = new(metav1.Now())
				pod.Finalizers = []string{finalizer}
			case "preempted":
				pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{Type: corev1.DisruptionTarget, Status: corev1.ConditionTrue, Reason: "PreemptionByScheduler"})
			case "failed":
				pod.Status.Phase = corev1.PodFailed
			case "succeeded":
				pod.Status.Phase = corev1.PodSucceeded
			case "foreign-node":
				pod.Spec.NodeName = "another-node"
			}
			reconciler, _ := fixtureReconciler(t, pod)
			if scenario == "missing" {
				if err := reconciler.client.Delete(t.Context(), pod); err != nil {
					t.Fatal(err)
				}
			}
			r, _, _ := cloudOwnershipFixture(t)
			if err := r.recordPod(original, reconciler.cfg, "a"); err != nil {
				t.Fatal(err)
			}
			if scenario == "delete-requested" || scenario == "deleted-record" || scenario == "terminal-record" {
				rec, secret, err := reconciler.ensureRecord(t.Context(), pod)
				if err != nil {
					t.Fatal(err)
				}
				rec.InstanceID = "i-owned"
				rec.DeleteRequested = scenario == "delete-requested"
				rec.Deleted = scenario == "deleted-record"
				if scenario == "terminal-record" {
					rec.TerminalStatus = &corev1.PodStatus{Phase: corev1.PodFailed}
				}
				if err := reconciler.save(t.Context(), rec, secret); err != nil {
					t.Fatal(err)
				}
			}
			var cloudCalls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				cloudCalls.Add(1)
				_, _ = w.Write([]byte(`{"items":[]}`))
			}))
			defer server.Close()
			r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
			h := &providerControlPlane{cfg: reconciler.cfg, client: reconciler.client}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err := r.waitBoot(ctx, h, reconciler.cfg, "a")
			if err == nil || !strings.Contains(err.Error(), "boot stopped") || ctx.Err() != nil || cloudCalls.Load() != 0 {
				t.Fatalf("lost or terminal Pod did not stop before Cloud polling: %v (calls=%d)", err, cloudCalls.Load())
			}
			data, err := os.ReadFile(filepath.Join(r.dir, "boot-failed-a.json"))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "preempted" && !strings.Contains(string(data), "PreemptionByScheduler") {
				t.Fatal("boot failure lost the scheduler's preemption reason")
			}
		})
	}
}

func TestCloudAcceptanceBootAllowsPendingSubmittedPod(t *testing.T) {
	pod := fixturePod()
	pod.Name, pod.Spec.NodeName, pod.Status.Phase = "cloud-a", "", corev1.PodPending
	reconciler, _ := fixtureReconciler(t, pod)
	r, _, _ := cloudOwnershipFixture(t)
	if err := r.recordPod(pod, reconciler.cfg, "a"); err != nil {
		t.Fatal(err)
	}
	h := &providerControlPlane{cfg: reconciler.cfg, client: reconciler.client}
	if _, err := r.bootPod(t.Context(), h, reconciler.cfg, "a"); err != nil {
		t.Fatalf("normal pending scheduling was treated as terminal: %v", err)
	}
}

func TestCloudAcceptanceCleanupCannotCreateAndConfirmsTermination(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "pre-existing"}[foreign], func(t *testing.T) {
			r, _, receipt := cloudOwnershipFixture(t)
			if foreign {
				r.ledger.Before[receipt.ID] = receipt
			}
			var terminated atomic.Bool
			var deletes, posts atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch req.Method {
				case http.MethodPost:
					posts.Add(1)
					http.Error(w, "refused", 500)
				case http.MethodDelete:
					deletes.Add(1)
					terminated.Store(true)
					w.WriteHeader(204)
				case http.MethodGet:
					raw, _ := json.Marshal(receipt)
					var item map[string]any
					_ = json.Unmarshal(raw, &item)
					item["status"] = "running"
					if terminated.Load() {
						item["status"] = "terminated"
					}
					if req.URL.Path == "/v1/instances" {
						_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{item}})
					} else {
						_ = json.NewEncoder(w).Encode(item)
					}
				default:
					http.Error(w, "refused", http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			r.api = &cloudClient{base: server.URL, token: "offline-test", http: server.Client()}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			err := r.cleanup(ctx)
			if posts.Load() != 0 {
				t.Fatal("cleanup attempted creation")
			}
			if foreign {
				if err == nil || deletes.Load() != 0 {
					t.Fatal("pre-existing instance was deletable")
				}
			} else if err != nil || deletes.Load() != 1 || !r.ledger.Complete {
				t.Fatalf("cleanup did not confirm termination: %v", err)
			}
		})
	}
}

func TestCloudAcceptanceUncertainCreateNeverCountsAsCleaned(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			t.Error("uncertain lookup mutated Cloud")
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := r.cleanup(ctx); err == nil || r.ledger.Complete {
		t.Fatal("uncertain create accepted as absent")
	}
}

func TestCloudAcceptanceUncertainSiblingDoesNotStarveKnownReceipt(t *testing.T) {
	r, a, receipt := cloudOwnershipFixture(t)
	a.Receipt = &receipt
	r.cleanupBudget = 20 * time.Millisecond
	r.ledger.Owned["b"] = &cloudOwned{Key: "pending", Attempted: true}
	var lookups atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			t.Error("unexpected cleanup mutation")
		}
		if req.URL.Path == "/v1/instances" {
			lookups.Add(1)
			_, _ = w.Write([]byte(`{"items":[]}`))
			return
		}
		raw, _ := json.Marshal(receipt)
		var item map[string]any
		_ = json.Unmarshal(raw, &item)
		item["status"] = "terminated"
		_ = json.NewEncoder(w).Encode(item)
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
	if err := r.cleanup(t.Context()); err == nil {
		t.Fatal("uncertain sibling accepted as clean")
	}
	if !r.ledger.Owned["a"].Terminated || r.ledger.Owned["b"].Terminated || r.ledger.Complete {
		t.Fatal("uncertain sibling starved confirmed cleanup")
	}
	if lookups.Load() != 1 {
		t.Fatal("known receipt incorrectly depended on idempotency lookup")
	}
}

func TestCloudAcceptanceInterruptedGateAndUnattemptedRecord(t *testing.T) {
	for _, phase := range []string{"gated", "before-post", "after-post", "no-proof"} {
		t.Run(phase, func(t *testing.T) {
			pod := fixturePod()
			pod.Name = "cloud-a"
			if phase == "gated" {
				pod.Spec.NodeName = ""
				pod.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: "acceptance.confidential.ai/durable-intent"}}
			}
			reconciler, _ := fixtureReconciler(t, pod)
			r, _, _ := cloudOwnershipFixture(t)
			r.ledger.Owned = map[string]*cloudOwned{}
			if err := r.recordPod(pod, reconciler.cfg, "a"); err != nil {
				t.Fatal(err)
			}
			if phase == "before-post" || phase == "after-post" {
				rec, secret, err := reconciler.ensureRecord(t.Context(), pod)
				if err != nil {
					t.Fatal(err)
				}
				if phase == "after-post" {
					rec.CreateAttempted = true
					if err = reconciler.save(t.Context(), rec, secret); err != nil {
						t.Fatal(err)
					}
				}
			}
			h := &providerControlPlane{cfg: reconciler.cfg, client: reconciler.client}
			if err := r.recoverUnattempted(t.Context(), h); err != nil {
				t.Fatal(err)
			}
			want := phase == "after-post" || phase == "no-proof"
			if r.ledger.Owned["a"].Attempted != want {
				t.Fatalf("interruption proof incorrectly changed create authority for %s", phase)
			}
		})
	}
}

func TestCloudAcceptanceRejectedObservationIsRetained(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	raw := []byte(`{"metadata":{"uid":"wrong"},"status":{}}`)
	if err := r.observation("failed", raw, map[string]any{"accepted": false, "failure": "UID differs"}, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(r.dir, "failed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status    json.RawMessage
		Readiness struct {
			Accepted bool
			Failure  string
		}
		AuthenticatedReadAccepted bool
	}
	if json.Unmarshal(data, &got) != nil || !got.AuthenticatedReadAccepted || got.Readiness.Accepted || got.Readiness.Failure == "" || !strings.Contains(string(got.Status), "wrong") {
		t.Fatal("rejected authenticated observation was lost")
	}
}

func TestCloudAcceptanceLocalCleanupRequiresStoppedProcessAndNoAuthority(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	held, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err = syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = closeCloudLocalState(dir); err == nil {
		t.Fatal("local cleanup ignored the live Go lock")
	}
	if err = syscall.Flock(int(held.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err = closeCloudLocalState(dir); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "closed-before-ledger.json")); err != nil {
		t.Fatal("delayed-run fence missing")
	}
	if err = cloudWrite(filepath.Join(dir, "cloud-authority-issued.json"), map[string]string{"run": "lost-ledger"}); err != nil {
		t.Fatal(err)
	}
	if err = closeCloudLocalState(dir); err == nil {
		t.Fatal("missing previously-issued ledger accepted as no authority")
	}
}

func TestCloudAcceptanceDelayedRunCannotCrossLocalCleanupFence(t *testing.T) {
	cfg := fixtureConfig(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfg.ImageManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	disk := strings.Repeat("a", 64)
	manifest["outputs"] = map[string]any{"disk_image": map[string]string{"sha256": disk}}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err = cloudWrite(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "tool")
	if err = os.WriteFile(binary, []byte("offline binary"), 0700); err != nil {
		t.Fatal(err)
	}
	input := cloudRunConfig{Source: strings.Repeat("1", 40), CloudURL: "https://api.cloud.confidential.ai", TokenFile: cfg.CloudTokenFile, Image: "c8s-pod@2026.10.27-1", CDSImage: "c8s-pod-cds@2026.10.27-1", ManifestFile: manifestPath, ManifestDigest: "sha256:" + cloudHash(raw), DiskDigest: "sha256:" + disk, CLIFile: binary, CLISHA256: cloudHash([]byte("offline binary")), ProbeFile: binary, ProbeSHA256: cloudHash([]byte("offline binary")), MeshImage: "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:" + strings.Repeat("b", 64), Size: "s1.2x", Location: "us-west-1", VCPUs: 2, MemoryMiB: 8192}
	path := filepath.Join(dir, "input.json")
	if err = cloudWrite(path, input); err != nil {
		t.Fatal(err)
	}
	if err = closeCloudLocalState(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("C8S_PODCLOUD_LIVE", "1")
	if opened, err := openCloudRun(path, dir, "run"); err == nil {
		opened.close()
		t.Fatal("delayed original run crossed the local cleanup fence")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "ledger.json")); !os.IsNotExist(err) {
		t.Fatal("fenced run issued Cloud authority")
	}
}

func TestCloudAcceptancePrivatePersistenceAndSymlinkRefusal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")
	if err := cloudWrite(path, map[string]string{"authority": "private"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("ledger permissions are not private")
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = cloudPrivateRead(link, 1024); err == nil {
		t.Fatal("private input followed a symlink")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = cloudPrivateRead(path, 1024); err == nil {
		t.Fatal("world-readable input accepted")
	}
}

func TestCloudAcceptanceWorkloadUsesAllocatedPeerAndExistingFixture(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	if _, _, err := r.workload("b", nil); err == nil {
		t.Fatal("B accepted without actual A endpoint")
	}
	peer := &endpoint{Host: "203.0.113.5", Port: 41080}
	pod, _, err := r.workload("b", peer)
	if err != nil {
		t.Fatal(err)
	}
	if pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 || pod.Annotations[Annotation] != "true" {
		t.Fatal("fixture bypasses the normal scheduler or durable intent gate")
	}
	var cfg struct {
		Peer struct {
			Host string
			Port int
		}
	}
	if json.Unmarshal([]byte(pod.Spec.Containers[0].Args[3]), &cfg) != nil || cfg.Peer.Host != peer.Host || cfg.Peer.Port != peer.Port {
		t.Fatal("fixture ignored allocated peer tuple")
	}
}
