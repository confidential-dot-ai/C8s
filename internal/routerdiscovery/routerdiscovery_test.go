package routerdiscovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// plainServingCert generates a self-signed ECDSA serving cert with NO armTLS
// extension — the shape a router front door presents.
func plainServingCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "router"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// discoveryDoc builds a router discovery document embedding cert + challenge.
// mode is the public_tls.mode field; "" mimics a pre-mode-field document.
func discoveryDoc(t *testing.T, cert *x509.Certificate, challenge []byte, mode, platform string, evidence string) []byte {
	t.Helper()
	doc, err := json.Marshal(types.DiscoveryDocument{
		Version: "1",
		PublicTLS: types.PublicTLSDiscovery{
			Mode: mode,
		},
		CDSTLS: types.CDSTLSDiscovery{
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		},
		Attestation: types.AttestationDiscovery{
			Challenge: base64.StdEncoding.EncodeToString(challenge),
			Platform:  platform,
			Evidence:  json.RawMessage(evidence),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// fakeLB serves the discovery document plus a proxied /allowlist body over TLS
// with servingCert (no armTLS extension), like a router front door.
func fakeLB(t *testing.T, servingCert tls.Certificate, doc []byte) *httptest.Server {
	t.Helper()
	return lbServer(t, &tls.Config{Certificates: []tls.Certificate{servingCert}}, routerHandler(doc))
}

// routerHandler answers the front-door routes the client uses: the discovery
// document, the proxied allowlist read, and an allowlist write.
func routerHandler(doc []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+DefaultPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(doc)
	})
	mux.HandleFunc("GET /allowlist", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`))
	})
	mux.HandleFunc("PUT /allowlist", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// lbServer serves h over any TLS configuration.
func lbServer(t *testing.T, cfg *tls.Config, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// approvingVerify stubs the verifier: approve, honoring the measurement-pin
// contract for measurement (the pin itself is unit-tested in localverify).
func approvingVerify(measurement []byte) localverify.VerifyFunc {
	return func(ctx context.Context, platform string, evidence json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		if len(p.Measurements) > 0 && !remote.MeasurementAllowed(measurement, p.Measurements) {
			return nil, localverify.ErrMeasurementNotAllowed
		}
		match := true
		return &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &match}, nil
	}
}

// TestNewVerifiedHTTPClient_EndToEnd is the regression test for the router
// allowlist bug: a front door whose serving cert has no armTLS extension must
// be verified via its discovery document (evidence bound to
// SHA-384(cert pubkey ‖ challenge)) and subsequent requests must succeed
// against the pinned serving cert.
func TestNewVerifiedHTTPClient_EndToEnd(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	challenge := []byte("issuance-challenge")
	doc := discoveryDoc(t, leaf, challenge, "cds", string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)

	measurement := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	erd, err := armtls.ReportDataForKey(leaf.PublicKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var sawVerify bool
	verify := func(ctx context.Context, platform string, evidence json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		sawVerify = true
		if platform != string(teetypes.PlatformAzSNP) {
			t.Fatalf("platform = %q, want az-snp", platform)
		}
		// az-snp binds through a TPM quote whose nonce is the unpadded 48-byte
		// digest — the verifier must receive exactly that anchor.
		if !bytes.Equal(p.ExpectedReportData, erd[:sha512.Size384]) {
			t.Fatalf("expected_report_data = %x, want %x", p.ExpectedReportData, erd[:sha512.Size384])
		}
		return approvingVerify(measurement)(ctx, platform, evidence, p)
	}

	hc, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, verify)
	if err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}
	if !sawVerify {
		t.Fatal("evidence verifier was not called")
	}

	// Two sequential requests: both must ride the one attested connection
	// (nothing closed it, so there is nothing to redial).
	for i := range 2 {
		resp, err := hc.Get(lb.URL + "/allowlist")
		if err != nil {
			t.Fatalf("GET /allowlist #%d through the connection-bound client: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"workloads"`)) {
			t.Fatalf("GET /allowlist #%d = %d %s", i+1, resp.StatusCode, body)
		}
	}
}

// The document's runtime extensions reach the verifier, which replays them
// against RTMR[3].
func TestNewVerifiedHTTPClient_PassesRuntimeExtensions(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	var d types.DiscoveryDocument
	if err := json.Unmarshal(discoveryDoc(t, leaf, []byte("issuance-challenge"), "cds", string(teetypes.PlatformTDX), `{"quote":"fake"}`), &d); err != nil {
		t.Fatal(err)
	}
	want := []string{"sha256:" + strings.Repeat("1", 64)}
	d.Attestation.RuntimeExtensions = want
	doc, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	lb := fakeLB(t, servingCert, doc)

	var got []string
	verify := func(ctx context.Context, platform string, evidence json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		got = p.RuntimeExtensions
		return approvingVerify(nil)(ctx, platform, evidence, p)
	}
	if _, err := NewVerifiedHTTPClient(context.Background(), lb.URL, nil, verify); err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("verifier got runtime extensions %v, want %v", got, want)
	}
}

// TestNewVerifiedHTTPClient_NoDiscovery proves a target without a discovery
// document (a direct CDS endpoint) signals ErrNoDiscovery so the caller falls
// back to armTLS serving-cert verification.
func TestNewVerifiedHTTPClient_NoDiscovery(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	_, err := NewVerifiedHTTPClient(context.Background(), srv.URL, nil, approvingVerify(nil))
	if !errors.Is(err, ErrNoDiscovery) {
		t.Fatalf("want ErrNoDiscovery, got: %v", err)
	}
}

// TestNewVerifiedHTTPClient_FailsClosed proves a discovery document that is
// present but fails verification is a hard error — NOT ErrNoDiscovery, which
// would let the caller fall back and mask an attack.
func TestNewVerifiedHTTPClient_FailsClosed(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	doc := discoveryDoc(t, leaf, []byte("challenge"), "", string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)

	errSignature := errors.New("signature verification failed")
	cases := []struct {
		name    string
		verify  localverify.VerifyFunc
		wantErr error
	}{
		{"verifier rejects", func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
			return nil, errSignature
		}, errSignature},
		{"measurement not allowed", approvingVerify(bytes.Repeat([]byte{0x01}, armtls.SNPMeasurementSize)),
			localverify.ErrMeasurementNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifiedHTTPClient(context.Background(), lb.URL,
				[][]byte{bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)}, tc.verify)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got: %v", tc.wantErr, err)
			}
			if errors.Is(err, ErrNoDiscovery) {
				t.Fatal("verification failure must not signal ErrNoDiscovery (would allow fallback)")
			}
		})
	}
}

// TestNewVerifiedHTTPClient_BindsDocCertToConnection proves the bootstrap
// fails when the document attests a cert other than the leaf the connection's
// handshake presented — a MITM, or a different router replica answering
// discovery than the one that terminated TLS.
func TestNewVerifiedHTTPClient_BindsDocCertToConnection(t *testing.T) {
	servingCert, _ := plainServingCert(t)
	_, otherLeaf := plainServingCert(t)
	// The doc attests otherLeaf; the server presents servingCert.
	doc := discoveryDoc(t, otherLeaf, []byte("challenge"), "cds", string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)

	_, err := NewVerifiedHTTPClient(context.Background(), lb.URL, nil, approvingVerify(nil))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("different router replica")) ||
		!bytes.Contains([]byte(err.Error()), []byte("renewing")) {
		t.Fatalf("want a doc-cert/connection-leaf binding failure naming both causes, got: %v", err)
	}
	if errors.Is(err, ErrNoDiscovery) {
		t.Fatal("binding failure must not signal ErrNoDiscovery (would allow fallback)")
	}
}

// TestNewVerifiedHTTPClient_PublicTLSModes proves the client accepts only the
// modes whose serving cert the evidence binds: cds (and empty, a pre-mode-field
// document), rejecting webpki, acme, and unknown modes with clear errors
// instead of returning a client whose handshakes can never match.
func TestNewVerifiedHTTPClient_PublicTLSModes(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	cases := []struct {
		mode    string
		wantErr string // empty = success
	}{
		{"cds", ""},
		{"", ""},
		{"webpki", "public_tls.mode=webpki is not supported"},
		{"acme", "public_tls.mode=acme is not supported"},
		{"tofu", `unknown public_tls.mode "tofu"`},
	}
	for _, tc := range cases {
		name := tc.mode
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			servingCert, leaf := plainServingCert(t)
			doc := discoveryDoc(t, leaf, []byte("challenge"), tc.mode, string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
			lb := fakeLB(t, servingCert, doc)

			_, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, approvingVerify(measurement))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewVerifiedHTTPClient: %v", err)
				}
				return
			}
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr)) {
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
			if errors.Is(err, ErrNoDiscovery) {
				t.Fatal("mode rejection must not signal ErrNoDiscovery (would allow fallback)")
			}
		})
	}
}

// TestNewVerifiedHTTPClient_RedialsToTheAttestedLeaf proves a lost attested
// connection is redialed and used when the new handshake presents the leaf
// the document attested: only the holder of the attested key can produce it,
// so the attestation covers the new connection as it did the first.
func TestNewVerifiedHTTPClient_RedialsToTheAttestedLeaf(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	doc := discoveryDoc(t, leaf, []byte("challenge"), "cds", string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)
	measurement := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)

	hc, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, approvingVerify(measurement))
	if err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}
	resp, err := hc.Get(lb.URL + "/allowlist")
	if err != nil {
		t.Fatalf("GET on the attested connection: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	lb.CloseClientConnections()

	resp, err = hc.Get(lb.URL + "/allowlist")
	if err != nil {
		t.Fatalf("GET after the attested connection was closed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET after redial = %d, want 200", resp.StatusCode)
	}
}

// TestAttestedDialerFailsClosedBeforeAttestation proves a connection lost
// before the document was verified fails closed: with no attested leaf there
// is nothing a redial could be bound to. A nil conn is the state after the
// discovery connection was handed out.
func TestAttestedDialerFailsClosedBeforeAttestation(t *testing.T) {
	d := &attestedDialer{}
	_, err := d.dial(context.Background(), "tcp", "")
	if err == nil || !strings.Contains(err.Error(), "lost before the discovery document was verified") {
		t.Fatalf("want a fail-closed error, got: %v", err)
	}
}

// TestNewAttestedTransportConfig pins the attested transport's shape: the
// timeout knobs mirror armtls.NewVerifyingHTTPClient and it serializes
// requests over one connection.
func TestNewAttestedTransportConfig(t *testing.T) {
	tr := newAttestedTransport(&attestedDialer{})
	if tr.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 10s", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}
	if tr.MaxIdleConns != 1 || tr.MaxConnsPerHost != 1 {
		t.Errorf("MaxIdleConns/MaxConnsPerHost = %d/%d, want 1/1", tr.MaxIdleConns, tr.MaxConnsPerHost)
	}
}

// TestNewVerifiedHTTPClient_RequiresHTTPS proves a non-https URL is rejected
// outright: the trust model binds attestation to a TLS handshake, which
// plaintext has none of.
func TestNewVerifiedHTTPClient_RequiresHTTPS(t *testing.T) {
	_, err := NewVerifiedHTTPClient(context.Background(), "http://cds.example", nil, approvingVerify(nil))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("scheme must be https")) {
		t.Fatalf("want an https-scheme error, got: %v", err)
	}
}

// TestNewVerifiedHTTPClient_RequiresVerifier proves a nil verifier fails
// closed at construction rather than skipping evidence verification.
func TestNewVerifiedHTTPClient_RequiresVerifier(t *testing.T) {
	_, err := NewVerifiedHTTPClient(context.Background(), "https://cds.example", nil, nil)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("verifier is required")) {
		t.Fatalf("want a nil-verifier error, got: %v", err)
	}
}

// TestNewVerifiedHTTPClient_RejectsExpiredServingCert proves the attested
// serving cert must be inside its validity window: the issuance-time evidence
// has no other freshness bound, so an expired cert fails closed — before the
// evidence verifier is even consulted — and never signals ErrNoDiscovery.
func TestNewVerifiedHTTPClient_RejectsExpiredServingCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "router"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		DNSNames:     []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	servingCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}

	doc := discoveryDoc(t, leaf, []byte("challenge"), "cds", string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)

	verifyCalls := 0
	verify := func(ctx context.Context, platform string, evidence json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		verifyCalls++
		return approvingVerify(nil)(ctx, platform, evidence, p)
	}

	_, err = NewVerifiedHTTPClient(context.Background(), lb.URL, nil, verify)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("expired")) {
		t.Fatalf("want an expiry rejection of the attested serving cert, got: %v", err)
	}
	if errors.Is(err, ErrNoDiscovery) {
		t.Fatal("validity failure must not signal ErrNoDiscovery (would allow fallback)")
	}
	if verifyCalls != 0 {
		t.Fatalf("an expired serving cert consumed %d evidence verification(s), want 0", verifyCalls)
	}
}

// TestNewVerifiedHTTPClient_RefusesRedialToAnotherLeaf proves the redial
// fails closed when the new handshake presents a leaf other than the attested
// one and no discovery document attests it: a different router replica
// (per-pod serving certs) that the verified document says nothing about.
func TestNewVerifiedHTTPClient_RefusesRedialToAnotherLeaf(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	otherCert, _ := plainServingCert(t)
	doc := discoveryDoc(t, leaf, []byte("challenge"), "cds", string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
	var handshakes, callerRequests atomic.Int32
	router := routerHandler(doc)
	// GetConfigForClient, not GetCertificate: the client dials an IP, so
	// the hello carries no server name and crypto/tls would skip the latter.
	lb := lbServer(t, &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 1 {
			return &tls.Config{Certificates: []tls.Certificate{servingCert}}, nil
		}
		return &tls.Config{Certificates: []tls.Certificate{otherCert}}, nil
	}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isBareDiscoveryFetch(r) {
			callerRequests.Add(1)
		}
		router.ServeHTTP(w, r)
	}))
	measurement := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)

	hc, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, approvingVerify(measurement))
	if err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}
	resp, err := hc.Get(lb.URL + "/allowlist")
	if err != nil {
		t.Fatalf("GET on the attested connection: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	lb.CloseClientConnections()
	requestsOnAttestedConn := callerRequests.Load()

	if _, err := hc.Get(lb.URL + "/allowlist"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("redial presented")) ||
		!bytes.Contains([]byte(err.Error()), []byte("renewing")) {
		t.Fatalf("want a refusal naming the leaf the redial presented and its causes, got: %v", err)
	}
	// The security property: the unattested peer receives at most the
	// discovery fetch that attests it, never a caller's request.
	if got := callerRequests.Load() - requestsOnAttestedConn; got != 0 {
		t.Fatalf("the server handled %d caller request(s) on the connection presenting another leaf, want 0", got)
	}
}

// isBareDiscoveryFetch reports whether r is the discovery GET an attestation
// sends: no credentials, no body.
func isBareDiscoveryFetch(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == DefaultPath &&
		r.Header.Get("Authorization") == "" && r.ContentLength == 0
}

// TestNewVerifiedHTTPClient_RedialsPerRequestWhenEveryResponseCloses proves a
// router that closes the connection after discovery and after every
// /allowlist request still serves reads and writes, each over a redial that
// presents the attested leaf.
func TestNewVerifiedHTTPClient_RedialsPerRequestWhenEveryResponseCloses(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	doc := discoveryDoc(t, leaf, []byte("challenge"), "cds", string(teetypes.PlatformAzSNP), `{"hcl_report":"fake"}`)
	measurement := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	var handshakes atomic.Int32
	lb := lbServer(t, &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		handshakes.Add(1)
		return &tls.Config{Certificates: []tls.Certificate{servingCert}}, nil
	}}, testutil.CloseEveryResponse(routerHandler(doc)))

	hc, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, approvingVerify(measurement))
	if err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}

	resp, err := hc.Get(lb.URL + "/allowlist")
	if err != nil {
		t.Fatalf("GET /allowlist after a closed discovery response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"workloads"`)) {
		t.Fatalf("GET /allowlist = %d %s", resp.StatusCode, body)
	}

	writes := []string{"web", "api"}
	for _, name := range writes {
		req, err := http.NewRequest(http.MethodPut, lb.URL+"/allowlist",
			strings.NewReader(`{"schema":"c8s.allowlist/v1","workloads":{"`+name+`":{"containers":[]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("PUT %s after a closed response: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("PUT %s = %d, want 204", name, resp.StatusCode)
		}
	}

	requestsSent := 2 + len(writes) // discovery, the read, each write
	if got := int(handshakes.Load()); got != requestsSent {
		t.Fatalf("server saw %d handshake(s) for %d requests, want one each", got, requestsSent)
	}
}

// evidenceLedger is a verifier stub for a testutil.RenewingRouter: it approves
// evidence, records which serving certs it approved, and refuses the evidence
// for the cert whose sha256 is refuse.
type evidenceLedger struct {
	mu       sync.Mutex
	approved map[string]bool
	refuse   string
}

func (l *evidenceLedger) verify(_ context.Context, _ string, evidence json.RawMessage, _ localverify.Params) (*teetypes.VerificationResult, error) {
	var ev testutil.RouterEvidence
	if err := json.Unmarshal(evidence, &ev); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if ev.ServingCertSHA256 == l.refuse {
		return nil, localverify.ErrMeasurementNotAllowed
	}
	l.approved[ev.ServingCertSHA256] = true
	match := true
	return &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &match}, nil
}

func (l *evidenceLedger) refuseEvidenceFor(cert *x509.Certificate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refuse = certSHA256(cert)
}

func (l *evidenceLedger) isApproved(cert *x509.Certificate) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.approved[certSHA256(cert)]
}

func certSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// servedLeaves records the serving cert each backend request arrived on.
type servedLeaves struct {
	mu     sync.Mutex
	leaves []*x509.Certificate
}

func (s *servedLeaves) add(cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaves = append(s.leaves, cert)
}

func (s *servedLeaves) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.leaves)
}

func (s *servedLeaves) last() *x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leaves[len(s.leaves)-1]
}

// TestNewVerifiedHTTPClient_ThroughARenewingRouter is the regression test for
// a router that renews its serving cert mid-session: once the attested
// connection is gone, the client attests the renewed leaf and sends the
// request over it, provided its evidence verifies and it names the same mesh
// CA key. Every request reaches only a leaf whose evidence was approved first.
func TestNewVerifiedHTTPClient_ThroughARenewingRouter(t *testing.T) {
	const putBody = `{"label":"v2"}`
	renew := func(r *testutil.RenewingRouter, _ *evidenceLedger) { r.Renew() }
	cases := []struct {
		name            string
		renew           func(*testutil.RenewingRouter, *evidenceLedger)
		routerCloses    bool // the router closes each connection after one request
		method          string
		wantRenewedLeaf bool   // on success: the request rode the renewed leaf, not the first
		wantErr         string // empty: the request succeeds
	}{
		{name: "renewal under a kept connection", renew: renew, method: http.MethodGet},
		{name: "GET on a new connection after a renewal", renew: renew, routerCloses: true, method: http.MethodGet, wantRenewedLeaf: true},
		{name: "PUT on a new connection after a renewal", renew: renew, routerCloses: true, method: http.MethodPut, wantRenewedLeaf: true},
		{
			name:         "renewed leaf the document does not attest yet",
			renew:        func(r *testutil.RenewingRouter, _ *evidenceLedger) { r.RenewLeaf() },
			routerCloses: true, method: http.MethodPut, wantErr: "renewing its certificate",
		},
		{
			name: "renewed leaf whose evidence fails the pins",
			renew: func(r *testutil.RenewingRouter, l *evidenceLedger) {
				r.Renew()
				l.refuseEvidenceFor(r.Leaf())
			},
			routerCloses: true, method: http.MethodPut, wantErr: localverify.ErrMeasurementNotAllowed.Error(),
		},
		{
			name:         "renewed leaf from another mesh CA",
			renew:        func(r *testutil.RenewingRouter, _ *evidenceLedger) { r.RenewUnderNewCA() },
			routerCloses: true, method: http.MethodPut, wantErr: "another mesh CA key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ledger := &evidenceLedger{approved: map[string]bool{}}
			served := &servedLeaves{}
			router := testutil.NewRenewingRouter(t, func(router *testutil.RenewingRouter) http.Handler {
				backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					leaf := router.LeafOf(r)
					if !ledger.isApproved(leaf) {
						t.Errorf("%s %s reached serving cert %s before its evidence was approved", r.Method, r.URL.Path, certSHA256(leaf))
					}
					if body, _ := io.ReadAll(r.Body); r.Method == http.MethodPut && string(body) != putBody {
						t.Errorf("PUT body = %q, want %q", body, putBody)
					}
					served.add(leaf)
				})
				if tc.routerCloses {
					return testutil.CloseEveryResponse(backend)
				}
				return backend
			})

			hc, err := NewVerifiedHTTPClient(context.Background(), router.URL, nil, ledger.verify)
			if err != nil {
				t.Fatalf("NewVerifiedHTTPClient: %v", err)
			}
			firstLeaf := router.Leaf()
			if err := send(hc, http.MethodGet, router.URL+"/allowlist", ""); err != nil {
				t.Fatalf("GET on the attested connection: %v", err)
			}
			tc.renew(router, ledger)

			body := ""
			if tc.method == http.MethodPut {
				body = putBody
			}
			err = send(hc, tc.method, router.URL+"/allowlist", body)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want an error containing %q, got: %v", tc.wantErr, err)
				}
				if served.count() != 1 {
					t.Fatalf("the backend saw %d requests, want only the first", served.count())
				}
				return
			}
			if err != nil {
				t.Fatalf("%s after the renewal: %v", tc.method, err)
			}
			wantLeaf := firstLeaf
			if tc.wantRenewedLeaf {
				wantLeaf = router.Leaf()
			}
			if got := served.last(); !got.Equal(wantLeaf) {
				t.Fatalf("%s rode serving cert %s, want %s", tc.method, certSHA256(got), certSHA256(wantLeaf))
			}
		})
	}
}

// TestNewVerifiedHTTPClient_DoesNotResendAReceivedWrite proves a PUT the router
// received is not sent again when its connection then drops, even though the
// router renewed meanwhile: only a request net/http never wrote is resent.
func TestNewVerifiedHTTPClient_DoesNotResendAReceivedWrite(t *testing.T) {
	var puts atomic.Int32
	router := testutil.NewRenewingRouter(t, func(router *testutil.RenewingRouter) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			puts.Add(1)
			router.Renew()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
		})
	})
	hc, err := NewVerifiedHTTPClient(context.Background(), router.URL, nil, approvingVerify(nil))
	if err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}

	if err := send(hc, http.MethodPut, router.URL+"/allowlist", `{"label":"v2"}`); err == nil {
		t.Fatal("want the PUT whose connection dropped to fail")
	}
	if n := puts.Load(); n != 1 {
		t.Fatalf("the router received the PUT %d times, want once", n)
	}
}

// send makes one request through hc and requires a 2xx response.
func send(hc *http.Client, method, url, body string) error {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s = %d", method, url, resp.StatusCode)
	}
	return nil
}
