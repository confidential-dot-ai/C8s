package cds

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

type changingMesh struct{ ca atomic.Pointer[issuer.CA] }

func (m *changingMesh) Current() (issuer.CurrentCA, bool) {
	ca := m.ca.Load()
	return issuer.CurrentCA{CA: ca}, ca != nil
}

func meshClientConnection(t *testing.T, ca *issuer.CA, expires time.Time) *tls.ConnectionState {
	t.Helper()
	template, err := certutil.NewLeafTemplate("test-client", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	template.NotBefore, template.NotAfter = expires.Add(-time.Hour), expires
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, ca.Key.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca.Cert}, VerifiedChains: [][]*x509.Certificate{{leaf, ca.Cert}}}
}

func TestCurrentMeshClientsRechecksAnEstablishedConnectionAfterFreshness(t *testing.T) {
	first, replacement := testMeshCA(t), testMeshCA(t)
	mesh := &changingMesh{}
	mesh.ca.Store(first.MeshCA.Current().CA)
	connection := meshClientConnection(t, first.MeshCA.Current().CA, time.Now().Add(time.Hour))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	guard := currentMeshClients(mesh, next)
	send := func(handler http.Handler) int {
		req := httptest.NewRequest(http.MethodGet, "/secrets/test", nil)
		req.TLS = connection // exactly the same handshake state on every request
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code
	}
	if code := send(guard); code != http.StatusNoContent {
		t.Fatalf("current mesh leaf: HTTP %d", code)
	}
	// A follower learns the rotation in its barrier. Checking the client
	// before that barrier would incorrectly authorize the old connection.
	fresh := haGate(func() bool { return true }, func() error {
		mesh.ca.Store(replacement.MeshCA.Current().CA)
		return nil
	}, guard)
	if code := send(fresh); code != http.StatusForbidden {
		t.Fatalf("old handshake after fresh rotation: HTTP %d", code)
	}
	connection = meshClientConnection(t, replacement.MeshCA.Current().CA, time.Now().Add(time.Hour))
	if code := send(guard); code != http.StatusNoContent {
		t.Fatalf("new mesh leaf: HTTP %d", code)
	}
}

func TestCurrentMeshClientsPreservesRenewedKeyAndFailsClosed(t *testing.T) {
	first := testMeshCA(t)
	mesh := &changingMesh{}
	original, _ := first.Current()
	mesh.ca.Store(original.CA)
	connection := meshClientConnection(t, original.CA, time.Now().Add(time.Hour))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	guard := currentMeshClients(mesh, next)
	send := func(path string, state *tls.ConnectionState) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.TLS = state
		response := httptest.NewRecorder()
		guard.ServeHTTP(response, req)
		return response.Code
	}
	if code := send("/secrets/test", connection); code != http.StatusNoContent {
		t.Fatalf("initial leaf: HTTP %d", code)
	}
	renewed, err := first.RenewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	mesh.ca.Store(renewed.CA)
	if code := send("/secrets/test", connection); code != http.StatusNoContent {
		t.Fatalf("same-key renewal invalidated an existing leaf: HTTP %d", code)
	}
	unverified := *connection
	unverified.VerifiedChains = nil
	if code := send("/secrets/test", &unverified); code != http.StatusForbidden {
		t.Fatalf("unverified client: HTTP %d", code)
	}
	expired := meshClientConnection(t, renewed.CA, time.Now().Add(-time.Minute))
	if code := send("/secrets/test", expired); code != http.StatusForbidden {
		t.Fatalf("expired client: HTTP %d", code)
	}
	mesh.ca.Store(nil)
	if code := send("/secrets/test", connection); code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable current CA: HTTP %d", code)
	}
	if code := send("/ca", nil); code != http.StatusNoContent {
		t.Fatalf("certificate-free caller: HTTP %d", code)
	}
	if code := send("/healthz", connection); code != http.StatusNoContent {
		t.Fatalf("health probe: HTTP %d", code)
	}
}
