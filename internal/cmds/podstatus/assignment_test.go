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

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
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
	doc := &podlaunch.Document{
		SchemaVersion: podlaunch.SchemaVersion, ClusterID: "cluster", Role: podlaunch.Pod,
		Node:                 podlaunch.Node{Name: "guest"},
		PodOperatorPublicKey: public(key),
		CDS:                  cmdsutil.CDS{Address: "cds.example.org:8443", Measurements: testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)},
		Image:                podlaunch.Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}},
	}
	store := &memoryAssignmentStore{}
	s, err := newAssignmentService(t.Context(), doc, store,
		func(context.Context) (*ecdsa.PublicKey, error) { return &key.PublicKey, nil },
		func(d *podlaunch.AssignedPod) (nodeservices.PodRuntime, error) {
			if d.CDS != doc.CDS {
				return nodeservices.PodRuntime{}, errors.New("assignment changed authenticated CDS trust")
			}
			return nodeservices.PodRuntime{UID: d.Pod.UID, Policy: []byte(d.Entries), Manifest: []byte(d.Pod.Manifest)}, nil
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

// One row per step's failure status, in step order (steps 2 to 9); every
// refusal leaves the record, the UID and the issued nonce unchanged.
func TestAssignmentRefusalsDoNotChangeState(t *testing.T) {
	for _, kind := range []string{"body", "unissued", "measured-key", "signature", "channel", "entries", "peers", "render", "runtime", "store"} {
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
				s.render = func(*podlaunch.AssignedPod) (nodeservices.PodRuntime, error) {
					return nodeservices.PodRuntime{}, errors.New("endpoint collision")
				}
			case "store":
				store.fail = true
				status = http.StatusServiceUnavailable
			}
			if kind == "entries" || kind == "peers" {
				var err error
				if req, err = podassign.Sign(key, peer, req); err != nil {
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

// One assignment per boot, a commit invalidates every nonce,
// and a restart keeps the assignment and refuses a second one.
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
}

// A refused assignment leaves its nonce held, a restart forgets every
// nonce; a replay answers 409 naming the held Pod.
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
	if rec := postAssignment(s, peer, data); rec.Code != http.StatusConflict || heldUID(t, rec) != s.assignedUID() {
		t.Fatal("replay was accepted or the conflict did not name the held Pod")
	}
}

// A guest that holds a Pod issues no nonce, in the boot that accepted the
// assignment and after a restart that restores it.
func TestAssignedGuestIssuesNoNonce(t *testing.T) {
	s, key, peer, store := assignmentFixture(t)
	if rec := postAssignment(s, peer, encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))); rec.Code != http.StatusOK {
		t.Fatalf("assignment: %d", rec.Code)
	}
	restarted, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, s.apply)
	if err != nil {
		t.Fatal(err)
	}
	for name, service := range map[string]*assignmentService{"assigned": s, "restarted": restarted} {
		if rec := serve(Handler{assignment: service}, http.MethodGet, AssignNoncePath); rec.Code != http.StatusConflict || heldUID(t, rec) != "pod-a" {
			t.Fatalf("%s guest answered a nonce request with %d %s", name, rec.Code, rec.Body)
		}
		if len(service.nonces) != 0 || len(service.issued) != 0 {
			t.Fatalf("%s guest kept a nonce", name)
		}
	}
}

// A nonce discarded at the bound is refused like one never issued.
func TestAssignmentNonceBoundDiscardsTheOldestUnusedNonce(t *testing.T) {
	s, key, peer, _ := assignmentFixture(t)
	first := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
	for range maxAssignmentNonces {
		if rec := serve(Handler{assignment: s}, http.MethodGet, AssignNoncePath); rec.Code != http.StatusOK {
			t.Fatal("issuance refused at the bound")
		}
	}
	if len(s.nonces) != maxAssignmentNonces || len(s.issued) != maxAssignmentNonces {
		t.Fatal("bound not held")
	}
	if rec := postAssignment(s, peer, first); rec.Code != http.StatusBadRequest || s.assignedUID() != "" {
		t.Fatal("the discarded nonce was accepted")
	}
	if rec := postAssignment(s, peer, encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))); rec.Code != http.StatusOK {
		t.Fatal("a fresh nonce after the discard was refused")
	}
}

// 405 on a wrong method and 404 on an unknown assignment route.
func TestAssignmentRoutes(t *testing.T) {
	s, _, _, _ := assignmentFixture(t)
	for _, path := range []string{AssignNoncePath, AssignPath} {
		if rec := serve(Handler{assignment: s}, http.MethodDelete, path); rec.Code != http.StatusMethodNotAllowed {
			t.Fatal("route accepted wrong method")
		}
	}
	if rec := serve(Handler{assignment: s}, http.MethodGet, "/v1/assign/other"); rec.Code != http.StatusNotFound {
		t.Fatal("unknown assignment route")
	}
}

// heldUID decodes the UID a 409 names.
func heldUID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		UID string `json:"uid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode conflict body %q: %v", rec.Body.String(), err)
	}
	return body.UID
}

// The signed client document reaches the guest renderer unchanged and
// survives a restart; a document altered after signing is refused, and a
// second assignment with another document cannot replace the first.
func TestAssignmentCarriesTheSignedClientDocument(t *testing.T) {
	s, key, peer, store := assignmentFixture(t)
	var rendered [][]byte
	render := s.render
	s.render = func(d *podlaunch.AssignedPod) (nodeservices.PodRuntime, error) {
		rendered = append(rendered, bytes.Clone(d.ClientDocument))
		return render(d)
	}
	withDocument := func(uid, document string) podassign.Request {
		req := issuedAssignment(t, s, key, peer, uid)
		req.ClientDocument = []byte(document)
		signed, err := podassign.Sign(key, peer, req)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	tampered := withDocument("pod-a", "client document")
	tampered.ClientDocument[0] ^= 1
	if rec := postAssignment(s, peer, encodeAssignment(t, tampered)); rec.Code != http.StatusUnauthorized || len(rendered) != 0 {
		t.Fatalf("altered client document: code=%d rendered=%d", rec.Code, len(rendered))
	}
	// Signed while the guest is unassigned: it issues no nonce afterwards.
	second := encodeAssignment(t, withDocument("pod-a", "another document"))
	if rec := postAssignment(s, peer, encodeAssignment(t, withDocument("pod-a", "client document"))); rec.Code != http.StatusOK {
		t.Fatalf("assignment: %d %s", rec.Code, rec.Body)
	}
	if rec := postAssignment(s, peer, second); rec.Code != http.StatusConflict {
		t.Fatalf("second assignment: %d", rec.Code)
	}
	if _, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, s.apply); err != nil {
		t.Fatal(err)
	}
	if len(rendered) != 2 || string(rendered[0]) != "client document" || string(rendered[1]) != "client document" {
		t.Fatalf("rendered client documents %q", rendered)
	}
}
