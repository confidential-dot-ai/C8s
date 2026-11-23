package volume

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	intsecrets "github.com/confidential-dot-ai/confidential-kubernetes/internal/secrets"
)

type fakeSigner struct {
	method, path string
	body         []byte
}

func (f *fakeSigner) Authorization(method, path string, body []byte) (string, error) {
	f.method, f.path, f.body = method, path, body
	return "Bearer test-token", nil
}

// putServer records the one request it receives and answers with status.
type putServer struct {
	status int
	gotReq intsecrets.PutRequest
	gotAuth,
	gotPath string
}

func (p *putServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.gotAuth = r.Header.Get("Authorization")
		p.gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &p.gotReq)
		w.WriteHeader(p.status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testBlob(t *testing.T) Blob {
	t.Helper()
	b, err := NewBlob("weights", testKey(), validVerity())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	return b
}

func TestPutBlobSendsTheBlobUnderTheOperatorToken(t *testing.T) {
	p := &putServer{status: http.StatusCreated}
	srv := p.start(t)
	signer := &fakeSigner{}

	if err := putBlob(t.Context(), srv.Client(), srv.URL, "/tenant-a/volumes/weights", testBlob(t), signer); err != nil {
		t.Fatalf("put: %v", err)
	}

	if p.gotPath != "/secrets/tenant-a/volumes/weights" {
		t.Errorf("path = %q", p.gotPath)
	}
	if p.gotAuth != "Bearer test-token" {
		t.Errorf("authorization = %q", p.gotAuth)
	}
	// The token must be bound to the same path and bytes the server received,
	// or the binding proves nothing about this request.
	if signer.path != p.gotPath {
		t.Errorf("token bound to %q, request went to %q", signer.path, p.gotPath)
	}
	if signer.method != http.MethodPut {
		t.Errorf("token bound to method %q", signer.method)
	}

	raw, err := base64.StdEncoding.DecodeString(p.gotReq.Value)
	if err != nil {
		t.Fatalf("value is not base64: %v", err)
	}
	got, err := DecodeBlob(raw)
	if err != nil {
		t.Fatalf("server received something that is not a key blob: %v", err)
	}
	if got.Key != testBlob(t).Key || got.Verity == nil || *got.Verity != validVerity() {
		t.Error("server received a different blob than was built")
	}
}

// A volume key and its ciphertext are one unit, so create never carries
// overwrite intent: replacing the key of a path some volume already uses
// strands that volume with no way back.
func TestPutBlobNeverAsksToOverwrite(t *testing.T) {
	p := &putServer{status: http.StatusCreated}
	srv := p.start(t)
	if err := putBlob(t.Context(), srv.Client(), srv.URL, "/a/b", testBlob(t), &fakeSigner{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if p.gotReq.Overwrite {
		t.Fatal("create asked CDS to overwrite")
	}
}

func TestPutBlobRefusesAnOccupiedPath(t *testing.T) {
	p := &putServer{status: http.StatusConflict}
	srv := p.start(t)
	err := putBlob(t.Context(), srv.Client(), srv.URL, "/a/b", testBlob(t), &fakeSigner{})
	if err == nil {
		t.Fatal("accepted a conflict")
	}
	if !strings.Contains(err.Error(), "not replaceable") {
		t.Errorf("error should say a volume key cannot be replaced: %v", err)
	}
}

func TestPutBlobSurfacesOtherStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError} {
		p := &putServer{status: status}
		srv := p.start(t)
		err := putBlob(t.Context(), srv.Client(), srv.URL, "/a/b", testBlob(t), &fakeSigner{})
		if err == nil {
			t.Errorf("status %d: accepted", status)
		}
	}
}
