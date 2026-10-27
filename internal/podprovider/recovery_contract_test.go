package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

func TestPersistedIntentCorruptionNeverReachesCloud(t *testing.T) {
	for _, kind := range []string{"foreign-secret", "invalid-json", "version", "origin", "node", "uid", "manifest", "signature", "signed-identity", "signed-document"} {
		t.Run(kind, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			rec, secret, err := r.ensureRecord(context.Background(), pod)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "foreign-secret":
				secret.Labels[ownerLabel] = "foreign-provider"
			case "version":
				rec.Version++
			case "origin":
				rec.CloudURL = "https://another-cloud.example"
			case "node":
				rec.NodeName = "another-node"
			case "uid":
				rec.UID = "another-pod"
			case "manifest":
				rec.Manifest = nil
			case "signature":
				rec.Request.Trust.InitData.Signature = []byte("invalid-signature")
			case "signed-identity":
				rec.Name = "another-name"
			case "signed-document":
				rec.Request.Trust.InitData.Document = []byte("not a launch document")
			}
			secret.Data["state.json"], err = json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "invalid-json" {
				secret.Data["state.json"] = []byte(`{"version":1,"unknown":true}`)
			}
			if err := r.client.Update(context.Background(), secret); err != nil {
				t.Fatal(err)
			}
			if err := reconcile(t, r, pod); err == nil {
				t.Fatal("corrupt intent accepted")
			}
			if cloud.createCalls != 0 || cloud.deleteCalls != 0 {
				t.Fatal("corrupt intent caused Cloud side effects")
			}
			if err := r.sweep(context.Background()); err == nil && kind != "foreign-secret" {
				t.Fatal("orphan sweep accepted corrupt owned record")
			}
			if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(secret), &corev1.Secret{}); err != nil {
				t.Fatal("corrupt cleanup evidence was discarded")
			}
		})
	}
}

func TestExistingIntentFreezesAllTrustInputs(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	rec, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	other := fixtureConfig(t)
	other.Image = "c8s-pod@different-version"
	other.workloads = `{"invalid":"new policy must not alter an existing intent"}`
	other.manifest = []byte("different manifest")
	other.ServerAddress = "198.51.100.77"
	other.MeshPeers = []string{"203.0.113.22:9443"}
	other.MemoryMiB = 16384
	r.cfg = other
	recovered, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("configuration change rewrote a frozen launch, signature, image manifest or capacity")
	}
	// Distinct metadata is irrelevant unless the guest consumed it through a
	// FieldRef. The external API object's scheduling metadata is also stripped.
	pod.Annotations["example.invalid/operator-note"] = "new"
	pod.Spec.NodeSelector = map[string]string{Annotation: "true"}
	pod.Spec.DeprecatedServiceAccount = "default"
	if err := matchesPod(recovered, pod); err != nil {
		t.Fatalf("unconsumed metadata affected frozen workload: %v", err)
	}
}

func TestCloudRecoveryRefusesAmbiguousAndForeignInstances(t *testing.T) {
	for _, kind := range []string{"lookup-failure", "foreign-owner", "missing-result", "existing-gone", "image-mismatch", "endpoints-pending", "pod-mutated", "node-unowned"} {
		t.Run(kind, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			switch kind {
			case "lookup-failure":
				cloud.find = func(string) (*instance, error) { return nil, errors.New("lookup unavailable") }
			case "foreign-owner":
				cloud.create = func(_ string, req createRequest) (*instance, error) {
					in := instanceFor(req)
					in.Labels["podcvm-provider"] = "foreign"
					return in, nil
				}
			case "missing-result":
				cloud.create = func(string, createRequest) (*instance, error) { return nil, nil }
			case "node-unowned":
				r.ownsNode = func(context.Context) error { return errors.New("node ownership changed") }
			default:
				if err := reconcile(t, r, pod); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "existing-gone":
					cloud.in = nil
				case "image-mismatch":
					cloud.in.Image.Version = "foreign-version"
				case "endpoints-pending":
					cloud.in.Endpoints = nil
				case "pod-mutated":
					current := getPod(t, r, pod)
					current.Spec.Containers[0].Args = []string{"changed"}
					if err := r.client.Update(context.Background(), current); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := reconcile(t, r, pod)
			if kind == "existing-gone" || kind == "image-mismatch" || kind == "endpoints-pending" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("ambiguous/foreign state was accepted")
			}
			got := getPod(t, r, pod)
			for _, c := range got.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					t.Fatal("untrusted or missing state was Ready")
				}
			}
			if got.Annotations[endpointsAnnotation] != "" {
				t.Fatal("untrusted endpoints advertised")
			}
			if cloud.createCalls > 1 {
				t.Fatal("same UID was recreated")
			}
			if kind == "lookup-failure" || kind == "node-unowned" {
				if cloud.createCalls != 0 {
					t.Fatal("launch occurred without authoritative lookup/ownership")
				}
			}
			if kind == "existing-gone" && got.Status.Phase != corev1.PodFailed {
				t.Fatal("lost instance did not make its UID terminal")
			}
		})
	}
}

func TestNeverAttemptedIntentCanBeDeletedWithoutCloudCreate(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	rec, secret, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	done, err := r.removeInstance(context.Background(), rec, secret)
	if err != nil || !done || cloud.createCalls != 0 || cloud.deleteCalls != 0 {
		t.Fatalf("unused intent cleanup: done=%t err=%v", done, err)
	}
	if !getRecord(t, r, pod).Deleted {
		t.Fatal("unused intent did not persist deletion")
	}
	// A Pod deleted before its durable record was created also releases its
	// finalizer; no VM create was possible before that record existed.
	if err := r.discard(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	current := getPod(t, r, pod)
	current.Finalizers = []string{finalizer}
	if err := r.client.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Delete(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unlaunched deleting Pod retained: %v", err)
	}
}

func TestDeletionNeverFollowsForeignRecoveryResult(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	rec, secret, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	cloud.in = instanceFor(rec.Request)
	cloud.in.Labels["podcvm-uid"] = "foreign"
	if done, err := r.removeInstance(context.Background(), rec, secret); err == nil || done {
		t.Fatal("foreign lookup result accepted during cleanup")
	}
	if cloud.deleteCalls != 0 || getRecord(t, r, pod).Deleted {
		t.Fatal("foreign result deleted or cleanup intent lost")
	}
}

func TestProjectionRequiresIdentityPhaseAndUniqueConditions(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	rec, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"name", "namespace", "phase", "condition-status", "duplicate-condition"} {
		t.Run(kind, func(t *testing.T) {
			p := fixtureProjection(rec)
			switch kind {
			case "name":
				p.Metadata.Name = rec.Name
			case "namespace":
				p.Metadata.Namespace = "foreign"
			case "phase":
				p.Status.Phase = "invalid"
			case "condition-status":
				p.Status.Conditions[0].Status = "invalid"
			case "duplicate-condition":
				p.Status.Conditions = append(p.Status.Conditions, p.Status.Conditions[0])
			}
			if _, err := projectedStatus(rec, p, pod, ""); err == nil {
				t.Fatal("invalid projection accepted")
			}
		})
	}
	p := fixtureProjection(rec)
	p.Status.Conditions = append(p.Status.Conditions, podstatus.PodCondition{Type: corev1.PodScheduled, Status: corev1.ConditionFalse})
	out, err := projectedStatus(rec, p, pod, "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if out.PodIP != "203.0.113.5" || len(out.PodIPs) != 1 || out.Conditions[0].Type != corev1.PodScheduled || out.Conditions[0].Status != corev1.ConditionTrue {
		t.Fatal("guest overwrote scheduler identity or dedicated Pod IP")
	}
}

func TestEndpointContractRejectsInvalidAddressesAndDuplicates(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	rec, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "::1", "status.example", "169.254.1.1"} {
		in := instanceFor(rec.Request)
		in.Endpoints[0].Host = host
		if _, _, _, err := endpoints(rec, in); err == nil {
			t.Fatalf("nonpublic endpoint accepted: %s", host)
		}
	}
	in := instanceFor(rec.Request)
	in.Endpoints = append(in.Endpoints, in.Endpoints[0])
	if _, _, _, err := endpoints(rec, in); err == nil {
		t.Fatal("duplicate public status endpoint accepted")
	}
	in = instanceFor(rec.Request)
	in.ID = "not-an-instance"
	if _, _, _, err := endpoints(rec, in); err == nil {
		t.Fatal("malformed instance ID accepted")
	}
}

func TestGuestMetadataSnapshotAndLaunchSizeBound(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	pod.Annotations["team"] = "tenant-one"
	pod.Annotations["kubernetes.io/config.hash"] = "untrusted"
	paths := []string{"metadata.namespace", "metadata.uid", "metadata.annotations['team']", "spec.nodeName"}
	for i, path := range paths {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{Name: strings.Repeat("A", i+1), ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}})
	}
	guest := guestPod(pod)
	if guest.Annotations["kubernetes.io/config.hash"] != "" || guest.Spec.Containers[0].Env[0].Value != pod.Namespace || guest.Spec.Containers[0].Env[1].Value != string(pod.UID) || guest.Spec.Containers[0].Env[2].Value != "tenant-one" || guest.Spec.Containers[0].Env[3].ValueFrom == nil {
		t.Fatal("guest metadata snapshot changed the Downward API contract")
	}
	pod.Annotations["large"] = strings.Repeat("x", 64<<10)
	if _, err := r.cfg.launch(pod); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("Cloud launch size limit not enforced: %v", err)
	}
}

type deletionSignalCloud struct {
	cloudAPI
	deleted chan struct{}
}

func (c *deletionSignalCloud) Delete(ctx context.Context, id string) error {
	err := c.cloudAPI.Delete(ctx, id)
	close(c.deleted)
	return err
}

func TestOrphanWorkerStopsAfterConfirmedCancellation(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	rec, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	cloud.in = instanceFor(rec.Request)
	if err := r.client.Delete(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	signal := &deletionSignalCloud{cloudAPI: cloud, deleted: make(chan struct{})}
	r.cloud = signal
	worker := &orphanWorker{reconciler: r}
	if !worker.NeedLeaderElection() || !(&virtualNode{}).NeedLeaderElection() {
		t.Fatal("side-effect workers must run only under leader election")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Start(ctx) }()
	select {
	case <-signal.deleted:
	case <-time.After(5 * time.Second):
		t.Fatal("orphan sweep did not initiate cleanup")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("orphan worker ignored cancellation")
	}
	if cloud.deleteCalls != 1 {
		t.Fatal("orphan worker continued Cloud calls after cancellation")
	}
	if getRecord(t, r, pod).Deleted {
		t.Fatal("orphan worker discarded unconfirmed deletion")
	}
	// Already-removed records are harmless to a delayed sweep event.
	if err := r.sweepRecord(context.Background(), "missing-record"); err != nil {
		t.Fatal(err)
	}
}
