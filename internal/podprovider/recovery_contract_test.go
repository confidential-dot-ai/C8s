package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

func TestPersistedIntentCorruptionNeverReachesCloud(t *testing.T) {
	for _, kind := range []string{"invalid-json", "uid"} {
		t.Run(kind, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			rec, secret, err := r.ensureRecord(context.Background(), pod)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "uid" {
				rec.UID = "another-pod"
			}
			secret.Data["state.json"], err = json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "invalid-json" {
				secret.Data["state.json"] = []byte(`{`)
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
			if err := r.sweep(context.Background()); err == nil {
				t.Fatal("orphan sweep accepted corrupt owned record")
			}
			stored := &corev1.Secret{}
			if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(secret), stored); err != nil {
				t.Fatal("corrupt cleanup evidence was discarded")
			}
			if !bytes.Equal(stored.Data["state.json"], secret.Data["state.json"]) {
				t.Fatal("refused state changed its durable cleanup evidence")
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
			if kind != "node-unowned" {
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

func TestProjectionRequiresIdentity(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	rec, _, err := r.ensureRecord(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"name", "namespace"} {
		t.Run(kind, func(t *testing.T) {
			p := fixtureProjection(rec)
			switch kind {
			case "name":
				p.Metadata.Name = rec.Name
			case "namespace":
				p.Metadata.Namespace = "foreign"
			}
			if _, err := projectedStatus(rec, p, pod, "", rec.Key); err == nil {
				t.Fatal("invalid projection accepted")
			}
		})
	}
	p := fixtureProjection(rec)
	p.Status.Conditions = append(p.Status.Conditions, podstatus.PodCondition{Type: corev1.PodScheduled, Status: corev1.ConditionFalse})
	out, err := projectedStatus(rec, p, pod, "203.0.113.5", rec.Key)
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
		if _, _, _, err := endpoints(rec.Request.Network, in); err == nil {
			t.Fatalf("nonpublic endpoint accepted: %s", host)
		}
	}
	in := instanceFor(rec.Request)
	in.Endpoints = append(in.Endpoints, in.Endpoints[0])
	if _, _, _, err := endpoints(rec.Request.Network, in); err == nil {
		t.Fatal("duplicate public status endpoint accepted")
	}
}
