//go:build linux && pod_cloud_integration

package acceptance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

// The generic launch record is durable, with its create attempt on the ledger,
// before the POST; a failed private write forwards nothing and leaves nothing
// a later lookup could adopt.
func TestCloudAcceptanceWarmCreateRequiresDurableRecordBeforePOST(t *testing.T) {
	r, cfg := launchFixture(t)
	r.cfg.Scenario = "warm-assignment"
	generic, err := r.prepareGeneric(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receipt := ownedReceipt(r, r.ledger.Owned["generic"], "i-warmowned")
	var posts atomic.Int64
	private := r.dir
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		item := instanceJSON(receipt, "running", 1)
		switch req.Method {
		case http.MethodPost:
			posts.Add(1)
			raw, e := os.ReadFile(filepath.Join(private, "ledger.json"))
			saved, e2 := os.ReadFile(filepath.Join(private, "launch-generic.json"))
			var ledger cloudLedger
			var durable record
			if e != nil || json.Unmarshal(raw, &ledger) != nil || ledger.Owned["generic"] == nil || !ledger.Owned["generic"].Attempted || ledger.Owned["generic"].Key != generic.Key || e2 != nil || json.Unmarshal(saved, &durable) != nil || !durable.CreateAttempted {
				t.Error("Cloud POST preceded exact durable generic intent")
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
	r.dir = filepath.Join(private, "absent")
	if err = r.create(t.Context(), generic, "generic"); err == nil || posts.Load() != 0 {
		t.Fatal("failed private persistence forwarded Cloud creation")
	}
	r.dir = private
	if saved, err := r.snapshot("generic"); err != nil || saved.CreateAttempted || saved.InstanceID != "" || generic.InstanceID != "" {
		t.Fatalf("failed write exposed tentative creation authority: %v", err)
	}
	if err = r.create(t.Context(), generic, "generic"); err != nil || posts.Load() != 1 || generic.InstanceID != receipt.ID {
		t.Fatalf("retry did not persist before forwarding: %v", err)
	}
	changed := *generic
	changed.Request.Trust.LaunchKey = "another launch key"
	if err = r.create(t.Context(), &changed, "generic"); err == nil || posts.Load() != 1 {
		t.Fatal("changed create request escaped the frozen launch")
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

func TestCloudAcceptanceWarmCleanupVisitsEveryLaunchAndKeepsCDSLast(t *testing.T) {
	r, _, receipt := cloudOwnershipFixture(t)
	original := r.ledger.Owned["a"]
	r.ledger.Owned = map[string]*cloudOwned{}
	var order []string
	var orderMu sync.Mutex
	receipts := map[string]cloudReceipt{}
	for _, name := range []string{"generic", "a", "cds"} {
		owned := *original
		owned.Key = "podcvm-" + name
		item := receipt
		item.Name = owned.Key
		item.ID = "i-" + name
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
		_ = json.NewEncoder(w).Encode(instanceJSON(item, "terminated", 1))
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, token: "offline", http: server.Client()}
	if err := r.cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	if !r.ledger.Complete || len(order) != 6 || order[len(order)-1] != "podcvm-cds" {
		t.Fatalf("incomplete or incorrectly ordered cleanup: %v", order)
	}
	for _, o := range r.ledger.Owned {
		if !o.Terminated {
			t.Fatal("generic or assigned launch was skipped")
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

// cloudAssignmentTestSession stands in for a verified generic guest: it signs
// with the launcher's key for a serving key it generated, verifies what it is
// sent, accepts the first assignment and refuses every later one.
type cloudAssignmentTestSession struct {
	t       *testing.T
	run     *cloudRun
	launch  *ecdsa.PrivateKey
	serving *ecdsa.PrivateKey
	generic *record
	calls   int
	key     []byte // Overrides the verified serving key when set.
}

func newAssignmentTestSession(t *testing.T, r *cloudRun, cfg *Config, generic *record) *cloudAssignmentTestSession {
	t.Helper()
	serving, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &cloudAssignmentTestSession{t: t, run: r, launch: cfg.key, serving: serving, generic: generic}
}

func (s *cloudAssignmentTestSession) ServingKey() []byte {
	if s.key != nil {
		return bytes.Clone(s.key)
	}
	der, err := x509.MarshalPKIXPublicKey(&s.serving.PublicKey)
	if err != nil {
		s.t.Fatal(err)
	}
	return der
}

func (s *cloudAssignmentTestSession) Prepare(_ context.Context, key *ecdsa.PrivateKey, manifest, entries, peers []byte) ([]byte, error) {
	req := podassign.Request{Nonce: make([]byte, podassign.NonceSize), Manifest: manifest, Entries: entries, MeshPeers: peers}
	if _, err := rand.Read(req.Nonce); err != nil {
		return nil, err
	}
	signed, err := podassign.Sign(key, &s.serving.PublicKey, req)
	if err != nil {
		return nil, err
	}
	return podassign.Encode(signed)
}

func (s *cloudAssignmentTestSession) Send(_ context.Context, body []byte) (string, error) {
	s.calls++
	request, err := podassign.Decode(body)
	if err != nil {
		return "", err
	}
	if err = podassign.Verify(&s.launch.PublicKey, &s.serving.PublicKey, request); err != nil {
		return "", err
	}
	pod, err := launchconfig.ParsePodManifest(request.Manifest)
	if err != nil {
		return "", err
	}
	if s.calls > 1 {
		return "", podstatus.ErrAlreadyAssigned
	}
	raw, err := cloudPrivateRead(filepath.Join(s.run.dir, "assignment-intent-"+s.generic.Key+".json"), 2<<20)
	var durable record
	if err != nil || json.Unmarshal(raw, &durable) != nil || !bytes.Equal(durable.Assignment, body) {
		s.t.Fatal("assignment POST preceded exact private durable evidence")
	}
	return string(pod.UID), nil
}

func (s *cloudAssignmentTestSession) Close() {}

func TestCloudAcceptanceWarmAssignmentWrapperFencesBytesAndRecordsConflict(t *testing.T) {
	for _, failure := range []string{"", "changed-body", "changed-allocation", "changed-serving-key", "no-receipt", "private-write"} {
		t.Run(failure, func(t *testing.T) {
			r, cfg := launchFixture(t)
			r.cfg.Scenario = "warm-assignment"
			generic, err := r.prepareGeneric(cfg)
			if err != nil {
				t.Fatal(err)
			}
			generic.CreateAttempted, generic.InstanceID = true, "i-warmowned"
			if err = r.saveRecord(generic, "generic"); err != nil {
				t.Fatal(err)
			}
			if failure != "no-receipt" {
				if err = r.updateLedger(func(l *cloudLedger) error {
					l.Owned["generic"].Receipt = &cloudReceipt{ID: generic.InstanceID}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			pod := fixturePod()
			rec, err := r.preparePod(cfg, pod, "a")
			if err != nil {
				t.Fatal(err)
			}
			base := newAssignmentTestSession(t, r, cfg, generic)
			observer := &cloudAssignmentObserver{run: r}
			session := observer.target(base, "generic")
			manifest, entries, peers, err := assignmentPayload(rec)
			if err != nil {
				t.Fatal(err)
			}
			body, err := session.Prepare(t.Context(), cfg.key, manifest, entries, peers)
			if err != nil {
				t.Fatal(err)
			}
			generic.Assignment, generic.ServingKey = body, session.ServingKey()
			if err = r.saveRecord(generic, "generic"); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "changed-body":
				body = append(bytes.Clone(body), ' ')
			case "changed-allocation":
				session.allocation = "other"
			case "changed-serving-key":
				base.key = []byte("different verified serving key")
			case "private-write":
				r.dir = filepath.Join(r.dir, "absent")
			}
			uid, err := session.Send(t.Context(), body)
			if failure != "" {
				if err == nil || base.calls != 0 {
					t.Fatalf("refused assignment reached its target: %v calls=%d", err, base.calls)
				}
				return
			}
			if err != nil || uid != string(pod.UID) || base.calls != 2 {
				t.Fatalf("assignment/conflict outcome: %s %v calls=%d", uid, err, base.calls)
			}
			if _, err = session.Send(t.Context(), body); !errors.Is(err, podstatus.ErrAlreadyAssigned) {
				t.Fatal("repeated primary POST was mistaken for a new acceptance")
			}
			if _, err = os.Stat(filepath.Join(r.dir, "assignment-accepted-"+generic.Key+".json")); err != nil {
				t.Fatal("accepted assignment left no evidence")
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
	if r.cfg.instanceCount() != 2 || len(pod.Spec.Containers) != 1 || len(pod.Spec.SchedulingGates) != 0 {
		t.Fatal("warm scenario lost its single assigned workload or two-instance budget")
	}
	if _, _, err = r.workload("b", nil); err == nil {
		t.Fatal("warm scenario accepted an unintended connected peer")
	}
}
