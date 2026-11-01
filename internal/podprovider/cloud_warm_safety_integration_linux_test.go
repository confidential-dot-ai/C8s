//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

func warmObserverFixture(t *testing.T, reader *Reconciler) *cloudRun {
	t.Helper()
	r, _, _ := cloudOwnershipFixture(t)
	r.cfg.Scenario = "warm-assignment"
	r.cfg.CloudURL = reader.cfg.CloudURL
	r.cfg.Image = reader.cfg.Image
	r.cfg.Size = reader.cfg.Size
	r.cfg.Location = reader.cfg.Location
	r.ledger.Run = reader.cfg.ProviderID
	r.ledger.CredentialHash = credentialHash(reader.cfg.token)
	r.ledger.Owned = map[string]*cloudOwned{}
	return r
}

func warmReceipt(r *cloudRun, p *poolRecord) cloudReceipt {
	in := cloudReceipt{ID: "i-warmowned", Name: p.Key, CreatedAt: p.CreatedAt, Tee: "tdx", Size: r.cfg.Size, Location: r.cfg.Location, Labels: p.Request.Labels}
	in.Image.Family, in.Image.Version, _ = strings.Cut(r.cfg.Image, "@")
	in.Image.Launch = "c8s-pod/1"
	in.Image.Digest = r.cfg.DiskDigest
	in.Attestation.ReferenceManifest.Digest = r.cfg.ManifestDigest
	in.Attestation.LaunchBinding.SHA256 = cloudHash([]byte(p.Request.Trust.LaunchKey))
	return in
}

func TestCloudAcceptanceWarmCreateRequiresDurableIntentAfterFailedSave(t *testing.T) {
	reader, _, _, _ := poolFixture(t)
	p, slot, err := reader.reservePool(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p.CreateAttempted = true
	if err = reader.savePool(t.Context(), p, slot); err != nil {
		t.Fatal(err)
	}
	r := warmObserverFixture(t, reader)
	receipt := warmReceipt(r, p)
	var posts atomic.Int64
	private := r.dir
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		wire, _ := json.Marshal(receipt)
		var item map[string]any
		_ = json.Unmarshal(wire, &item)
		item["status"] = "running"
		switch req.Method {
		case http.MethodPost:
			posts.Add(1)
			raw, e := os.ReadFile(filepath.Join(private, "ledger.json"))
			var ledger cloudLedger
			if e != nil || json.Unmarshal(raw, &ledger) != nil || ledger.Owned[p.Key] == nil || !ledger.Owned[p.Key].Attempted || ledger.Owned[p.Key].SlotUID != string(slot.UID) {
				t.Error("Cloud POST preceded exact durable allocation")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{item}})
		case http.MethodGet:
			if req.URL.Path == "/v1/instances" {
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{item}})
			} else {
				_ = json.NewEncoder(w).Encode(item)
			}
		default:
			t.Error("unexpected mutation")
			http.Error(w, "refused", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
	tracked := &cloudTrackedAPI{run: r, reader: reader}
	r.dir = filepath.Join(private, "absent")
	if _, err = tracked.Create(t.Context(), p.Key, p.Request); err == nil || posts.Load() != 0 {
		t.Fatal("failed private persistence forwarded Cloud creation")
	}
	if _, _, err = r.ownedSnapshot(p.Key); err == nil {
		t.Fatal("failed write exposed tentative creation authority")
	}
	r.dir = private
	// A subsequent lookup must not turn the failed write into creation authority.
	if _, err = tracked.Find(t.Context(), p.Key); err == nil {
		t.Fatal("failed create-intent write allowed adopting a discovered instance")
	}
	owned, _, err := r.ownedSnapshot(p.Key)
	if err != nil || owned.Attempted || owned.Receipt != nil {
		t.Fatal("discovery retained unissued creation authority")
	}
	if err = r.cleanup(t.Context()); err == nil || posts.Load() != 0 {
		t.Fatal("failed create-intent write authorized cleanup or provisioning")
	}
	if _, err = tracked.Create(t.Context(), p.Key, p.Request); err != nil || posts.Load() != 1 {
		t.Fatalf("retry did not persist before forwarding: %v", err)
	}
	changed := p.Request
	changed.Size = "different"
	if _, err = tracked.Create(t.Context(), p.Key, changed); err == nil || posts.Load() != 1 {
		t.Fatal("changed create request escaped frozen allocation")
	}
}

func TestCloudAcceptanceWarmUnattemptedDiscoveryNeverAuthorizesCleanup(t *testing.T) {
	r, o, receipt := cloudOwnershipFixture(t)
	o.Attempted = false
	var deletes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			deletes.Add(1)
			http.Error(w, "refused", http.StatusMethodNotAllowed)
			return
		}
		if req.URL.Path == "/v1/instances" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []cloudReceipt{receipt}})
		} else {
			_ = json.NewEncoder(w).Encode(receipt)
		}
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
	if err := r.cleanup(t.Context()); err == nil || deletes.Load() != 0 || o.Receipt != nil || r.ledger.Complete {
		t.Fatal("unattempted discovery became cleanup authority")
	}
}

func TestCloudAcceptanceWarmCleanupVisitsEveryGenerationAndKeepsCDSLast(t *testing.T) {
	r, _, receipt := cloudOwnershipFixture(t)
	original := r.ledger.Owned["a"]
	r.ledger.Owned = map[string]*cloudOwned{}
	var order []string
	var orderMu sync.Mutex
	receipts := map[string]cloudReceipt{}
	for _, name := range []string{"podcvm-refill", "podcvm-claimed", "cds"} {
		owned := *original
		owned.Key = name
		item := receipt
		item.Name = name
		item.ID = "i-" + strings.ReplaceAll(name, "-", "")
		owned.Receipt = &item
		r.ledger.Owned[name] = &owned
		receipts[item.ID] = item
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			t.Error("cleanup mutated terminated instances")
			http.Error(w, "refused", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(req.URL.Path, "/v1/instances/")
		item, ok := receipts[id]
		if !ok {
			t.Error("cleanup used discovery instead of exact receipts")
			http.Error(w, "missing", 404)
			return
		}
		orderMu.Lock()
		order = append(order, item.Name)
		orderMu.Unlock()
		data, _ := json.Marshal(item)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		body["status"] = "terminated"
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
	if err := r.cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	if !r.ledger.Complete || len(order) != 6 || order[len(order)-1] != "cds" {
		t.Fatalf("incomplete or incorrectly ordered cleanup: %v", order)
	}
	for _, o := range r.ledger.Owned {
		if !o.Terminated {
			t.Fatal("unclaimed or claimed generation was skipped")
		}
	}
}

func TestCloudAcceptanceWarmLedgerSnapshotsAreIndependentDuringConcurrentUpdates(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for range 8 {
		wg.Go(func() {
			if err := r.updateLedger(func(ledger *cloudLedger) error { ledger.Owned["a"].Attempted = true; return nil }); err != nil {
				failures <- err
				return
			}
			copy, _, err := r.ownedSnapshot("a")
			if err != nil {
				failures <- err
				return
			}
			copy.Labels["podcvm-provider"] = "foreign"
			copy.Terminated = true
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	current, _, err := r.ownedSnapshot("a")
	if err != nil || current.Terminated || current.Labels["podcvm-provider"] != r.ledger.Run {
		t.Fatal("snapshot exposed mutable ledger authority")
	}
}

type cloudAssignmentTestSession struct {
	assignmentSession
	t       *testing.T
	reader  *Reconciler
	run     *cloudRun
	pool    *poolRecord
	calls   int
	serving []byte
}

func (s *cloudAssignmentTestSession) ServingKey() []byte {
	if s.serving != nil {
		return bytes.Clone(s.serving)
	}
	return s.assignmentSession.ServingKey()
}

func (s *cloudAssignmentTestSession) Send(_ context.Context, body []byte) (string, error) {
	s.calls++
	request, err := podassign.Decode(body)
	if err != nil {
		return "", err
	}
	peer, err := x509.ParsePKIXPublicKey(s.ServingKey())
	if err != nil {
		return "", err
	}
	if err = podassign.Verify(&s.reader.cfg.key.PublicKey, peer, request); err != nil {
		return "", err
	}
	pod, err := launchconfig.ParsePodManifest(request.Manifest)
	if err != nil {
		return "", err
	}
	if s.calls > 1 {
		return "", podstatus.ErrAlreadyAssigned
	}
	raw, err := cloudPrivateRead(filepath.Join(s.run.dir, "assignment-intent-"+s.pool.Key+".json"), 2<<20)
	var secret corev1.Secret
	var durable poolRecord
	if err != nil || json.Unmarshal(raw, &secret) != nil || json.Unmarshal(secret.Data["state.json"], &durable) != nil || !bytes.Equal(durable.Assignment, body) {
		s.t.Fatal("assignment POST preceded exact private durable evidence")
	}
	return string(pod.UID), nil
}

func TestCloudAcceptanceWarmAssignmentWrapperFencesBytesAndRecordsConflict(t *testing.T) {
	for _, failure := range []string{"", "changed-body", "changed-slot-uid", "changed-serving-key", "private-write"} {
		t.Run(failure, func(t *testing.T) {
			reader, _, guest, pod := poolFixture(t)
			if err := reader.maintainPools(t.Context()); err != nil {
				t.Fatal(err)
			}
			rec, secret, err := reader.ensureRecord(t.Context(), pod)
			if err != nil {
				t.Fatal(err)
			}
			p, slot, err := reader.selectPool(t.Context(), rec, secret)
			if err != nil {
				t.Fatal(err)
			}
			r := warmObserverFixture(t, reader)
			if err = r.recordPod(pod, reader.cfg, "a"); err != nil {
				t.Fatal(err)
			}
			if err = r.recordCloudPool(p, slot, true); err != nil {
				t.Fatal(err)
			}
			if err = r.updateLedger(func(l *cloudLedger) error { l.Owned[p.Key].Receipt = &cloudReceipt{ID: p.InstanceID}; return nil }); err != nil {
				t.Fatal(err)
			}
			base := &cloudAssignmentTestSession{assignmentSession: &poolSession{guest: guest, pool: p}, t: t, reader: reader, run: r, pool: p}
			observer := &cloudAssignmentObserver{run: r, reader: reader}
			session := &cloudObservedAssignment{assignmentSession: base, observer: observer, allocation: p.Key}
			manifest, entries, peers, err := assignmentPayload(rec)
			if err != nil {
				t.Fatal(err)
			}
			body, err := session.Prepare(t.Context(), reader.cfg.key, manifest, entries, peers)
			if err != nil {
				t.Fatal(err)
			}
			p.Assignment, p.ServingKey = body, session.ServingKey()
			if err = reader.savePool(t.Context(), p, slot); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "changed-body":
				body = append(bytes.Clone(body), ' ')
			case "changed-slot-uid":
				rec.Pool.UID = "replacement"
				if err = reader.save(t.Context(), rec, secret); err != nil {
					t.Fatal(err)
				}
			case "changed-serving-key":
				base.serving = []byte("different verified serving key")
			case "private-write":
				r.dir = filepath.Join(r.dir, "absent")
			}
			uid, err := session.Send(t.Context(), body)
			if failure != "" {
				if err == nil || base.calls != 0 {
					t.Fatal("refused assignment reached its target")
				}
				return
			}
			if err != nil || uid != string(pod.UID) || base.calls != 2 {
				t.Fatalf("assignment/conflict outcome: %s %v calls=%d", uid, err, base.calls)
			}
			if _, err = session.Send(t.Context(), body); !errors.Is(err, podstatus.ErrAlreadyAssigned) {
				t.Fatal("repeated primary POST was mistaken for a new acceptance")
			}
		})
	}
}

func TestCloudAcceptanceWarmWorkloadAndCapacityRemainBounded(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	r.cfg.Scenario = "warm-assignment"
	pod, _, err := r.workload("a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.instanceCount() != 3 || len(pod.Spec.Containers) != 1 || pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 {
		t.Fatal("warm scenario lost its independent scheduled workload or three-instance budget")
	}
	if _, _, err = r.workload("b", nil); err == nil {
		t.Fatal("warm scenario accepted an unintended connected peer")
	}
}

func TestCloudAcceptanceWarmTerminationRequiresHeldPodFinalizer(t *testing.T) {
	for _, state := range []string{"valid", "missing-pod", "replaced-uid", "missing-finalizer", "not-deleting"} {
		t.Run(state, func(t *testing.T) {
			reader, _, _, pod := poolFixture(t)
			if err := reader.maintainPools(t.Context()); err != nil {
				t.Fatal(err)
			}
			rec, secret, err := reader.ensureRecord(t.Context(), pod)
			if err != nil {
				t.Fatal(err)
			}
			p, slot, err := reader.selectPool(t.Context(), rec, secret)
			if err != nil {
				t.Fatal(err)
			}
			rec.DeleteRequested, p.DeleteRequested = true, true
			p.InstanceID = "i-warmowned"
			if err = reader.save(t.Context(), rec, secret); err != nil {
				t.Fatal(err)
			}
			if err = reader.savePool(t.Context(), p, slot); err != nil {
				t.Fatal(err)
			}
			deleting := pod.DeepCopy()
			deleting.Finalizers = []string{finalizer}
			deleting.DeletionTimestamp = new(metav1.Now())
			switch state {
			case "replaced-uid":
				deleting.UID = "replacement-pod"
			case "missing-finalizer":
				deleting.Finalizers = []string{"test.invalid/unrelated"}
			case "not-deleting":
				deleting.DeletionTimestamp = nil
			}
			objects := []client.Object{secret, slot}
			if state != "missing-pod" {
				objects = append(objects, deleting)
			}
			reader.client = fake.NewClientBuilder().WithScheme(reader.client.Scheme()).WithObjects(objects...).Build()
			r := warmObserverFixture(t, reader)
			if err = r.recordCloudPool(p, slot, true); err != nil {
				t.Fatal(err)
			}
			receipt := warmReceipt(r, p)
			if err = r.updateLedger(func(ledger *cloudLedger) error {
				ledger.Owned[p.Key].Receipt = &receipt
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet || req.URL.Path != "/v1/instances/"+receipt.ID {
					t.Error("termination observation mutated Cloud or used inexact discovery")
					http.Error(w, "refused", http.StatusMethodNotAllowed)
					return
				}
				raw, _ := json.Marshal(receipt)
				var body map[string]any
				_ = json.Unmarshal(raw, &body)
				body["status"] = "terminated"
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
			tracked := &cloudTrackedAPI{run: r, reader: reader}
			in, err := tracked.Get(t.Context(), receipt.ID)
			if state == "valid" {
				if err != nil || in == nil || in.Status != "terminated" {
					t.Fatalf("retained Pod finalizer did not permit termination observation: %v", err)
				}
				if err = r.checkWarmTermination(p, string(slot.UID)); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || in != nil {
					t.Fatal("missing exact Pod finalizer authorized termination proof")
				}
				if _, err = os.Stat(filepath.Join(r.dir, "termination-"+p.Key+".json")); !os.IsNotExist(err) {
					t.Fatal("refused termination observation wrote a passing receipt")
				}
			}
			current, currentSlot, err := reader.loadPool(t.Context(), slot.Name)
			if err != nil || currentSlot.UID != slot.UID || !current.DeleteRequested || current.Deleted {
				t.Fatal("termination observation released allocation cleanup authority")
			}
			currentPod, currentSecret, err := reader.loadRecord(t.Context(), secret.Name)
			if err != nil || currentSecret.UID != secret.UID || !currentPod.DeleteRequested || currentPod.Deleted {
				t.Fatal("termination observation released Pod cleanup authority")
			}
		})
	}
}
