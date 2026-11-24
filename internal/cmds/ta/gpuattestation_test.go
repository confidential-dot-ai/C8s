package ta

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

func TestOnlyCurrentMembersCanReadAnAdmittedWorkerNetwork(t *testing.T) {
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"10.40.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := armtls.MarshalSandboxIDExtension(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), Extensions: []pkix.Extension{ext}}
	verified := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}, PeerCertificates: []*x509.Certificate{leaf}}
	callbacks := 0
	router := chi.NewRouter()
	router.Method(http.MethodGet, workloadclaims.GPUAttestationPrefix+"{host}", workerGPUAttestation(hosts, func(_ context.Context, ip netip.Addr) ([]byte, error) {
		callbacks++
		if ip.String() != "10.40.0.2" {
			return nil, errors.New("worker unavailable")
		}
		return []byte(`{"status":"no_gpu"}`), nil
	}))
	check := func(host string, peer *tls.ConnectionState, want, calls int) {
		t.Helper()
		req := httptest.NewRequest("GET", workloadclaims.GPUAttestationPrefix+host, nil)
		req.TLS = peer
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != want || callbacks != calls {
			t.Fatalf("%s returned %d with %d worker reads", host, w.Code, callbacks)
		}
	}
	check("10.40.0.2", nil, 403, 0)
	check("10.40.0.2", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, 403, 0)
	check("127.0.0.1", verified, 400, 0)
	check("10.41.0.2", verified, 400, 0)
	check("10.40.0.2", verified, 200, 1)
	check("10.40.0.3", verified, 502, 2)
	leaf.NotAfter = time.Now().Add(-time.Second)
	check("10.40.0.2", verified, 403, 2)
}
