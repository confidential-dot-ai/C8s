package allowlist

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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/routerdiscovery"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// routerServer stands in for the router front door: a TLS server whose serving
// cert carries NO armTLS extension, serving its discovery document plus the
// CDS allowlist read handler it proxies.
func routerServer(t *testing.T, measurementChallenge []byte) *httptest.Server {
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
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := json.Marshal(types.DiscoveryDocument{
		Version: "1",
		CDSTLS: types.CDSTLSDiscovery{
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		},
		Attestation: types.AttestationDiscovery{
			Challenge: base64.StdEncoding.EncodeToString(measurementChallenge),
			Platform:  string(teetypes.PlatformAzSNP),
			Evidence:  json.RawMessage(`{"hcl_report":"fake"}`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+routerdiscovery.DefaultPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(doc)
	})
	mux.HandleFunc("GET /allowlist", seededAllowlistHandler(t))

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// seededAllowlistHandler serves a canonical allowlist (one entry admitting
// digA) as CDS's read endpoint would.
func seededAllowlistHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	al := pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: anyWorkloads(t, map[string]string{digA: "registry/c8s/cds@" + digA}),
	}
	body, err := al.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"1"`)
		w.Write(body)
	}
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

// runCmdWith executes the allowlist command with an injected evidence verifier.
func runCmdWith(verify localverify.VerifyFunc, args ...string) (string, string, error) {
	cmd := newCmd(testutil.VerifierStub(verify))
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

// TestListThroughRouter is the regression test for `c8s allowlist list` against
// a router front door: the serving cert has no armTLS extension (OID
// 1.3.6.1.4.1.66378.1.1), so the CLI must verify the LB's discovery document
// instead of failing the handshake, then read the allowlist over the pinned
// cert.
func TestListThroughRouter(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	lb := routerServer(t, []byte("issuance-challenge"))

	out, errOut, err := runCmdWith(approvingVerify(measurement), "list",
		"--url", lb.URL,
		"--measurements", hex.EncodeToString(measurement),
	)
	if err != nil {
		t.Fatalf("list through router failed: %v (stderr: %s)", err, errOut)
	}
	if !strings.Contains(out, digA) {
		t.Fatalf("output missing seeded digest %s:\n%s", digA, out)
	}
}

// TestListThroughRouterFailsClosed proves a front door whose discovery evidence
// does not verify is rejected outright — no fallback, no allowlist read.
func TestListThroughRouterFailsClosed(t *testing.T) {
	pinned := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	reported := bytes.Repeat([]byte{0x01}, armtls.SNPMeasurementSize)
	lb := routerServer(t, []byte("issuance-challenge"))

	_, _, err := runCmdWith(approvingVerify(reported), "list",
		"--url", lb.URL,
		"--measurements", hex.EncodeToString(pinned),
	)
	if err == nil {
		t.Fatal("expected a measurement mismatch to fail the command")
	}
	if !strings.Contains(err.Error(), "discovery document verification failed") {
		t.Fatalf("want a discovery verification error, got: %v", err)
	}
}

// armtlsCDSServer stands in for a port-forwarded CDS: a TLS server whose
// serving cert DOES carry the armTLS extension (an embedded az-snp envelope),
// serving the allowlist read handler and no discovery document.
func armtlsCDSServer(t *testing.T) *httptest.Server {
	t.Helper()

	key, _, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{
		Family: armtls.TEETypeSEVSNP,
		Report: []byte(`{"platform":"az-snp","evidence":{"hcl_report":"fake"}}`),
	}
	der, err := armtls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /allowlist", seededAllowlistHandler(t))

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestListDirectARMTLS drives the non-fronted path end to end: no discovery
// document (ErrNoDiscovery fallback), so the CLI verifies the armTLS serving
// cert in-process — the verifier must receive the embedded envelope and the
// cert-key anchor — then reads the allowlist over the verified handshake.
func TestListDirectARMTLS(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	cds := armtlsCDSServer(t)

	var sawVerify bool
	verify := func(ctx context.Context, platform string, evidence json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		sawVerify = true
		if platform != string(teetypes.PlatformAzSNP) {
			t.Fatalf("platform = %q, want az-snp", platform)
		}
		if len(p.ExpectedReportData) != sha512.Size384 {
			t.Fatalf("expected_report_data is %d bytes, want the unpadded %d-byte cert-key anchor", len(p.ExpectedReportData), sha512.Size384)
		}
		return approvingVerify(measurement)(ctx, platform, evidence, p)
	}

	out, errOut, err := runCmdWith(verify, "list",
		"--url", cds.URL,
		"--measurements", hex.EncodeToString(measurement),
	)
	if err != nil {
		t.Fatalf("list against a direct armTLS CDS failed: %v (stderr: %s)", err, errOut)
	}
	if !sawVerify {
		t.Fatal("evidence verifier was not called")
	}
	if !strings.Contains(out, digA) {
		t.Fatalf("output missing seeded digest %s:\n%s", digA, out)
	}
}

// TestListDirectARMTLSFailsClosed proves a serving cert whose evidence the
// verifier rejects never serves a read: the handshake itself fails.
func TestListDirectARMTLSFailsClosed(t *testing.T) {
	pinned := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	reported := bytes.Repeat([]byte{0x01}, armtls.SNPMeasurementSize)
	cds := armtlsCDSServer(t)

	_, _, err := runCmdWith(approvingVerify(reported), "list",
		"--url", cds.URL,
		"--measurements", hex.EncodeToString(pinned),
	)
	if err == nil {
		t.Fatal("expected a measurement mismatch to fail the command")
	}
	if !strings.Contains(err.Error(), "peer attestation failed") {
		t.Fatalf("want a peer-attestation failure from the handshake, got: %v", err)
	}
}
