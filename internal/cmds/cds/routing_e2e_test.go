package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// e2eCDS is the production CDS router serving /routes and /operator-keys over
// armTLS, with evidence from a stub attestation-api. It authorizes writes
// under key and publishes published at /operator-keys.
type e2eCDS struct {
	url    string
	client *http.Client // verifies the CDS like the router does
}

func startE2ECDS(t *testing.T, stub *mockapi.Stub, pin []byte, mesh *issuer.CA, key, published *ecdsa.PublicKey) *e2eCDS {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(published)
	if err != nil {
		t.Fatal(err)
	}
	router := newRouter(dependencies{
		Routes: routeHandler{
			Store:     inMemoryStore(t),
			Authorize: operatorauth.Verifier{Keys: []*ecdsa.PublicKey{key}, ClockSkew: 30 * time.Second}.Authorize,
			MeshCA:    mesh.Cert,
		},
		OperatorKeysPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		ReadyFn:          func() bool { return true },
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	})
	tlsCfg, certs, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), stub.URL()),
		CertTTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := certs.WarmUp(t.Context()); err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: router, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &e2eCDS{url: "https://" + ln.Addr().String(), client: verifyingClient(t, stub, pin)}
}

func verifyingClient(t *testing.T, stub *mockapi.Stub, pin []byte) *http.Client {
	t.Helper()
	client, err := armtls.NewVerifyingHTTPClient(armtls.Pins{Measurements: [][]byte{pin}}, stub.URL())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// put stores manifest under signer, as `c8s routes put` does.
func (c *e2eCDS) put(t *testing.T, signer *operatorauth.Signer, manifest []byte) {
	t.Helper()
	auth, err := signer.Authorization(http.MethodPut, routes.Path, manifest)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, c.url+routes.Path, bytes.NewReader(manifest))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", auth)
	resp, err := c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT /routes = %d %s, want %d", resp.StatusCode, body, http.StatusNoContent)
	}
}

// e2eRouter is the routing engine wired as cds-attest wires it.
type e2eRouter struct {
	state  *routing.State
	poller *routing.Poller
	proxy  *routing.Proxy
}

func newE2ERouter(t *testing.T, stub *mockapi.Stub, cdsURL string, pin []byte, mesh *issuer.CA) *e2eRouter {
	t.Helper()
	cds, err := routing.NewCDSClient(cdsURL, verifyingClient(t, stub, pin))
	if err != nil {
		t.Fatal(err)
	}
	identity := e2ePublishedIdentity(t, e2eNamedLeaf(t, mesh, "router"), mesh)
	state := routing.NewState(routing.StateConfig{MeshCAs: identity.MeshCAs})
	transports := routing.NewTransports(routing.TransportConfig{MeshIdentity: identity.Credential})
	return &e2eRouter{
		state: state,
		poller: routing.NewPoller(routing.PollerConfig{
			State: state, Fetcher: cds, Keys: cds, Transports: transports, Interval: time.Hour,
		}),
		proxy: routing.NewProxy(routing.ProxyConfig{State: state, Transports: transports, Timeout: 10 * time.Second}),
	}
}

// e2ePublishedIdentity publishes leaf and ca as one credential generation on a
// volume shaped like the one get-cert publishes on, and reads the router's mesh
// identity from it.
func e2ePublishedIdentity(t *testing.T, leaf tls.Certificate, ca *issuer.CA) *routing.MeshIdentity {
	t.Helper()
	key, ok := leaf.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("leaf key is %T, want an ECDSA key", leaf.PrivateKey)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	generation := filepath.Join("generations", "1")
	if err := os.MkdirAll(filepath.Join(dir, generation), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"tls.crt": certutil.EncodeCertPEM(leaf.Certificate[0]),
		"tls.key": keyPEM,
		"ca.crt":  certutil.EncodeCertPEM(ca.Cert.Raw),
	} {
		if err := os.WriteFile(filepath.Join(dir, generation, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(generation, filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	identity, err := routing.NewMeshIdentity(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		filepath.Join(dir, "ca.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// e2eSandboxID is the workload instance a member leaf names.
const e2eSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

func e2eNamedLeaf(t *testing.T, ca *issuer.CA, workload string) tls.Certificate {
	t.Helper()
	csrPEM, key := generateCSR(t)
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.SignCSR(issuer.SignCSRParams{CSR: csr, TTL: 30 * time.Minute, SandboxID: e2eSandboxID, MatchedWorkload: &armtls.MatchedWorkload{
		Name: workload, AllowlistVersion: "1", AllowlistDigest: bytes.Repeat([]byte{0x42}, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// TestRoutesEndToEnd: an operator stores a manifest on the CDS; the router
// fetches it over armTLS through the production verifying client, checks it
// under the pinned operator key set, and routes a request to the workload
// backend it names. A substituted operator key set or a wrong CDS pin applies
// nothing.
func TestRoutesEndToEnd(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, 48)
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(measurement)))
	mesh, err := issuer.NewCA("mesh ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, key := operatorSigner(t)

	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "web saw "+r.RequestURI)
	}))
	// A member backend serves the mesh profile: its endpoint holds its leaf,
	// answers the mesh protocol and carries plain HTTP inside it.
	testutil.ServeMeshBackend(web, e2eNamedLeaf(t, mesh, "web"))
	web.StartTLS()
	t.Cleanup(web.Close)
	manifest := func(revision int) []byte {
		b, err := json.Marshal(map[string]any{
			"schema": routes.Schema, "revision": revision, "notBefore": "2020-01-01T00:00:00Z", "maxAgeSeconds": 3600,
			"hosts": map[string]any{"app.example": map[string]any{"routes": []any{map[string]any{
				"path": "/", "match": "prefix",
				"backend": map[string]string{"address": web.Listener.Addr().String(), "workload": "web"},
			}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("routes by the stored manifest", func(t *testing.T) {
		cds := startE2ECDS(t, stub, measurement, mesh, key, key)
		cds.put(t, signer, manifest(1))
		router := newE2ERouter(t, stub, cds.url, measurement, mesh)
		if err := router.poller.Poll(t.Context()); err != nil {
			t.Fatalf("Poll() = %v, want nil", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		r.Host = "app.example"
		w := httptest.NewRecorder()
		router.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Body.String() != "web saw /v1/models" {
			t.Fatalf("GET /v1/models = %d %q, want 200 %q", w.Code, w.Body, "web saw /v1/models")
		}
	})
	t.Run("A1 wrong CDS pin", func(t *testing.T) {
		cds := startE2ECDS(t, stub, measurement, mesh, key, key)
		cds.put(t, signer, manifest(1))
		router := newE2ERouter(t, stub, cds.url, bytes.Repeat([]byte{0x43}, 48), mesh)
		// The TLS stack flattens the verification error to text.
		if err := router.poller.Poll(t.Context()); err == nil || !strings.Contains(err.Error(), remote.ErrMeasurementNotAllowed.Error()) {
			t.Fatalf("Poll() under a wrong CDS pin = %v, want %q", err, remote.ErrMeasurementNotAllowed)
		}
		if router.state.Current() != nil {
			t.Fatal("Current() != nil under a wrong CDS pin, want nothing applied")
		}
	})
	t.Run("W2 W6 substituted operator key set", func(t *testing.T) {
		_, other := operatorSigner(t)
		cds := startE2ECDS(t, stub, measurement, mesh, key, other)
		cds.put(t, signer, manifest(1))
		router := newE2ERouter(t, stub, cds.url, measurement, mesh)
		if err := router.poller.Poll(t.Context()); err == nil {
			t.Fatal("Poll() under a substituted operator key set = nil, want an error")
		}
		if router.state.Current() != nil {
			t.Fatal("Current() != nil under a substituted operator key set, want nothing applied")
		}
	})
}
