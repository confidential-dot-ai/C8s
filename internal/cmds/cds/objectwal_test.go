package cds

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

type gatedObjectNode struct {
	clusterNode
	err   error
	reads int
}

func (n *gatedObjectNode) ConfirmRead() error     { n.reads++; return n.err }
func (n *gatedObjectNode) Serving() cdsha.Serving { return cdsha.Serving{OK: true} }

func TestObjectWALGateConfirmsReadsAndAllowsCredentialRecovery(t *testing.T) {
	n := &gatedObjectNode{err: errors.New("S3 unavailable")}
	r := &clusterCDS{node: n}
	called := false
	h := r.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
	for _, path := range []string{"/secrets/pilot/key", "/attest", "/measurements", "/ca"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable || called {
			t.Fatalf("served %s without fresh storage", path)
		}
	}
	if n.reads != 4 {
		t.Fatal("requests did not confirm read watermarks")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, objectProvisionPath, nil))
	if w.Code != http.StatusNoContent || !called {
		t.Fatal("expired credentials cannot be reprovisioned during outage")
	}
	n.err = nil
	called = false
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ca", nil))
	if w.Code != http.StatusNoContent || !called {
		t.Fatal("fresh replica did not serve")
	}
}

func TestProvisionParserRejectsTrailingAndUnknownData(t *testing.T) {
	for _, body := range []string{`{}`, `{"key":"AA==","credentials":{}}`, `{"unexpected":true}`, `{} {}`} {
		if _, err := parseProvision([]byte(body)); err == nil {
			t.Fatal("accepted invalid provisioning document")
		}
	}
}
