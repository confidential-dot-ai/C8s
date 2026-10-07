package routerdiscovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
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
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DefaultPath:
			w.Header().Set("Content-Type", "application/json")
			w.Write(doc)
		case "/allowlist":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{servingCert}}
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
	// (the client never redials).
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
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("different router replica")) {
		t.Fatalf("want a doc-cert/connection-leaf binding failure, got: %v", err)
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

// TestNewVerifiedHTTPClient_FailsClosedOnReconnect proves the client never
// redials once the attested connection is gone: a new handshake could land on
// a different router replica (per-pod serving certs) that the verified
// document says nothing about.
func TestNewVerifiedHTTPClient_FailsClosedOnReconnect(t *testing.T) {
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

	if _, err := hc.Get(lb.URL + "/allowlist"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("re-run the command")) {
		t.Fatalf("want a fail-closed redial refusal, got: %v", err)
	}
}

// TestNewSingleConnClientConfig pins the connection-bound client's shape: the
// timeout knobs mirror armtls.NewVerifyingHTTPClient and the transport is
// limited to the single attested connection.
func TestNewSingleConnClientConfig(t *testing.T) {
	hc := newSingleConnClient(nil)
	if hc.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", hc.Timeout)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", hc.Transport)
	}
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
