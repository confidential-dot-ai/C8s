package podstatus

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const assignmentEntries = "{\"schema\":\"c8s.allowlist/v1\",\"workloads\":{}}"

type memoryAssignmentStore struct {
	record  *assignmentRecord
	fail    bool
	commits int
}

func (m *memoryAssignmentStore) Load() (*assignmentRecord, error) { return m.record, nil }
func (m *memoryAssignmentStore) Commit(r *assignmentRecord) error {
	if m.fail {
		return errors.New("storage failure")
	}
	if m.record != nil {
		return errors.New("already recorded")
	}
	m.record = r
	m.commits++
	return nil
}

func assignmentFixture(t *testing.T) (*assignmentService, *ecdsa.PrivateKey, *ecdsa.PublicKey, *memoryAssignmentStore) {
	t.Helper()
	key := ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey)
	server := ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey)
	public := func(k *ecdsa.PrivateKey) string {
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	doc := &launchconfig.Document{
		SchemaVersion: launchconfig.SchemaVersion, ClusterID: "cluster", Role: launchconfig.Pod,
		Node: launchconfig.Node{Name: "guest"}, Server: launchconfig.ServerConfig{Address: "192.0.2.1", OperatorPublicKey: public(server)},
		PodOperatorPublicKey: public(key),
		CDS:                  launchconfig.CDS{Address: "cds.example.org:8443", Measurements: testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)},
		Image:                launchconfig.Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}},
	}
	store := &memoryAssignmentStore{}
	s, err := newAssignmentService(t.Context(), doc, store,
		func(context.Context) (*ecdsa.PublicKey, error) { return &key.PublicKey, nil },
		func(d *launchconfig.Document) (nodeservices.PodRuntime, error) {
			if d.CDS != doc.CDS {
				return nodeservices.PodRuntime{}, errors.New("assignment changed authenticated CDS trust")
			}
			return nodeservices.PodRuntime{UID: d.Pod.UID, Policy: []byte(d.Workloads), Manifest: []byte(d.Pod.Manifest)}, nil
		},
		func(context.Context) error { return nil },
		func(context.Context, nodeservices.PodRuntime) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return s, key, &server.PublicKey, store
}

func assignmentManifest(uid string) []byte {
	return []byte("{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"app\",\"namespace\":\"tenant\",\"uid\":\"" + uid + "\"},\"spec\":{\"containers\":[{\"name\":\"app\",\"image\":\"repo@sha256:" + strings.Repeat("a", 64) + "\"}]}}")
}

func issuedAssignment(t *testing.T, s *assignmentService, key *ecdsa.PrivateKey, peer *ecdsa.PublicKey, uid string) podassign.Request {
	t.Helper()
	rec := serve(Handler{assignment: s}, http.MethodGet, AssignNoncePath)
	if rec.Code != http.StatusOK {
		t.Fatalf("nonce: %d", rec.Code)
	}
	var nonce struct{ Nonce []byte }
	if err := json.Unmarshal(rec.Body.Bytes(), &nonce); err != nil {
		t.Fatal(err)
	}
	req, err := podassign.Sign(key, peer, podassign.Request{Nonce: nonce.Nonce, Manifest: assignmentManifest(uid), Entries: []byte(assignmentEntries), MeshPeers: []byte("[]")})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func postAssignment(s *assignmentService, peer *ecdsa.PublicKey, data []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, AssignPath, bytes.NewReader(data))
	req = req.WithContext(armtls.WithServingKey(req.Context(), peer))
	rec := httptest.NewRecorder()
	Handler{assignment: s}.ServeHTTP(rec, req)
	return rec
}

func encodeAssignment(t *testing.T, req podassign.Request) []byte {
	t.Helper()
	data, err := podassign.Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAssignmentRefusalsDoNotChangeState(t *testing.T) {
	for _, kind := range []string{"body", "unissued", "signature", "channel", "manifest", "entries", "peers", "measured-key", "runtime", "render", "store"} {
		t.Run(kind, func(t *testing.T) {
			s, key, peer, store := assignmentFixture(t)
			req := issuedAssignment(t, s, key, peer, "pod-a")
			status := http.StatusUnprocessableEntity
			switch kind {
			case "unissued":
				req.Nonce = bytes.Repeat([]byte{7}, podassign.NonceSize)
				status = http.StatusBadRequest
			case "signature":
				req.Signature[0] ^= 1
				status = http.StatusUnauthorized
			case "channel":
				peer = &ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey
				status = http.StatusUnauthorized
			case "manifest":
				req.Manifest = []byte("{}")
			case "entries":
				req.Entries = []byte("{\"schema\":\"c8s.allowlist/v1\",\"workloads\":{\"x\":{\"containers\":[{\"role\":\"mesh\"}]}}}")
			case "peers":
				req.MeshPeers = []byte("[\"169.254.169.254:80\"]")
			case "measured-key":
				s.boundKey = func(context.Context) (*ecdsa.PublicKey, error) { return nil, errors.New("private binding diagnostic") }
				status = http.StatusServiceUnavailable
			case "runtime":
				s.available = func(context.Context) error { return errors.New("private runtime diagnostic") }
				status = http.StatusServiceUnavailable
			case "render":
				s.render = func(*launchconfig.Document) (nodeservices.PodRuntime, error) {
					return nodeservices.PodRuntime{}, errors.New("endpoint collision")
				}
			case "store":
				store.fail = true
				status = http.StatusServiceUnavailable
			}
			if kind == "manifest" || kind == "entries" || kind == "peers" {
				var err error
				req, err = podassign.Sign(key, peer, req)
				if err != nil {
					t.Fatal(err)
				}
			}
			data := encodeAssignment(t, req)
			if kind == "body" {
				data = []byte("{}")
				status = http.StatusBadRequest
			}
			rec := postAssignment(s, peer, data)
			if rec.Code != status || store.record != nil || s.assignedUID() != "" || len(s.nonces) != 1 || strings.Contains(rec.Body.String(), "private") {
				t.Fatalf("refusal changed authority or exposed detail: code=%d, body=%s", rec.Code, rec.Body)
			}
		})
	}
}

func TestAssignmentConcurrentCommitAndRecovery(t *testing.T) {
	s, key, peer, store := assignmentFixture(t)
	first := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
	second := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-b"))
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, body := range [][]byte{first, second} {
		wg.Go(func() { codes <- postAssignment(s, peer, body).Code })
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 || store.commits != 1 || s.runtime == nil || len(s.nonces) != 0 {
		t.Fatalf("assignment was not atomic: %v commits=%d", counts, store.commits)
	}
	uid := s.assignedUID()
	restored, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, s.apply)
	if err != nil {
		t.Fatal(err)
	}
	if restored.assignedUID() != uid || restored.runtime == nil || !bytes.Equal(restored.runtime.Manifest, s.runtime.Manifest) {
		t.Fatal("restart lost its accepted assignment")
	}
	rotated := &ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey
	if rec := postAssignment(restored, rotated, first); rec.Code != http.StatusConflict {
		t.Fatal("new serving key reopened assignment")
	}
	// Signature verification on recovery uses the original serving key; changing
	// the record itself is rejected rather than treated as an unassigned boot.
	store.record.ServingKey, _ = x509.MarshalPKIXPublicKey(rotated)
	if _, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, s.apply); err == nil {
		t.Fatal("altered assignment record recovered")
	}
}

func TestAssignmentStorageFailureCanRetryButRestartForgetsNonce(t *testing.T) {
	s, key, peer, store := assignmentFixture(t)
	data := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
	store.fail = true
	if rec := postAssignment(s, peer, data); rec.Code != http.StatusServiceUnavailable {
		t.Fatal(rec.Code)
	}
	store.fail = false
	restarted, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, s.apply)
	if err != nil {
		t.Fatal(err)
	}
	if rec := postAssignment(restarted, peer, data); rec.Code != http.StatusBadRequest {
		t.Fatal("service restart retained an unused nonce")
	}
	if rec := postAssignment(s, peer, data); rec.Code != http.StatusOK {
		t.Fatal("uncommitted storage failure consumed the nonce")
	}
	if rec := postAssignment(s, peer, data); rec.Code != http.StatusConflict {
		t.Fatal("replay was accepted")
	}
}

func TestAssignmentNonceCapacityNeverEvictsAnIssuedNonce(t *testing.T) {
	s, key, peer, _ := assignmentFixture(t)
	first := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
	for range maxAssignmentNonces - 1 {
		if rec := serve(Handler{assignment: s}, http.MethodGet, AssignNoncePath); rec.Code != http.StatusOK {
			t.Fatal(rec.Code)
		}
	}
	if rec := serve(Handler{assignment: s}, http.MethodGet, AssignNoncePath); rec.Code != http.StatusServiceUnavailable {
		t.Fatal("unbounded issuance")
	}
	if rec := postAssignment(s, peer, first); rec.Code != http.StatusOK {
		t.Fatal("old issued nonce was evicted")
	}
}

func TestAssignmentRoutesAndStaticLaunchConflict(t *testing.T) {
	s, key, peer, _ := assignmentFixture(t)
	data := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
	s.doc.Pod = &launchconfig.PodSpec{UID: "static"}
	static, err := newAssignmentService(t.Context(), s.doc, nil, s.boundKey, s.render, s.available, s.apply)
	if err != nil {
		t.Fatal(err)
	}
	if rec := postAssignment(static, peer, data); rec.Code != http.StatusConflict {
		t.Fatal("static launch accepted assignment")
	}
	for _, path := range []string{AssignNoncePath, AssignPath} {
		if rec := serve(Handler{assignment: s}, http.MethodDelete, path); rec.Code != http.StatusMethodNotAllowed {
			t.Fatal("route accepted wrong method")
		}
	}
	if rec := serve(Handler{assignment: s}, http.MethodGet, "/v1/assign/other"); rec.Code != http.StatusNotFound {
		t.Fatal("unknown assignment route")
	}
}
