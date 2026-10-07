package cdsca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// testMeasurement is a syntactically valid SHA-384 launch measurement. Its
// value is returned by the injected verifier, allowing image-policy tests
// to check the endpoint pin before the command reads the CA.
const testMeasurement = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// meshCA mints a self-signed CA certificate standing in for one CDS's mesh CA.
// Two calls produce two distinct CAs.
func meshCA(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// armtlsServingCert mints the self-signed armTLS serving cert a direct CDS
// presents, so the read travels the same attested path it uses in production.
func armtlsServingCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformAzSNP,
		Evidence: json.RawMessage(`{"hcl_report":"fake"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := armtls.MarshalExtension(&armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: embedded})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "cds"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		DNSNames:        []string{"localhost"},
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// newAttestedCDS serves GET /ca over armTLS with the given status and body, and
// counts the requests that reach it.
func newAttestedCDS(t *testing.T, status int, body []byte) (*int, string) {
	t.Helper()
	seen := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/ca", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{armtlsServingCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &seen, srv.URL
}

// servingPEM renders what a CDS answers at /ca.
func servingPEM(ders ...[]byte) []byte {
	var buf bytes.Buffer
	for _, der := range ders {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return buf.Bytes()
}

// run drives the CLI with an attestation verifier that approves, so the only
// thing under test is what the command does with a verified endpoint.
func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	approve := func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		match := true
		result := &teetypes.VerificationResult{Platform: teetypes.PlatformAzSNP, SignatureValid: true, ReportDataMatch: &match}
		result.Claims.LaunchDigest = testMeasurement
		return result, nil
	}
	cmd := newCmd(testutil.VerifierStub(approve))
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

// The bundle this command emits becomes the anchor every --mesh-ca check runs
// against, so reading it from an endpoint whose build is not pinned would
// launder "any attested TEE" into a pin. The refusal lands before any request.
func TestRefusesAnUnpinnedCDS(t *testing.T) {
	seen, url := newAttestedCDS(t, http.StatusOK, servingPEM(meshCA(t, "cds-m")))

	_, _, err := run(t, "--url", url)
	if err == nil {
		t.Fatal("a read from an endpoint with no --measurements was accepted")
	}
	if !strings.Contains(err.Error(), "--measurements") {
		t.Fatalf("refusal does not name --measurements: %v", err)
	}
	if *seen != 0 {
		t.Fatalf("the refused read still sent %d request(s)", *seen)
	}
}

// Plaintext carries no attestation, so nothing read over it can serve as an
// anchor — --insecure buys a read here the way it buys one elsewhere.
func TestRefusesAPlaintextURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(servingPEM(meshCA(t, "cds-m")))
	}))
	t.Cleanup(srv.Close)

	_, _, err := run(t, "--url", srv.URL, "--measurements", testMeasurement, "--insecure")
	if err == nil {
		t.Fatal("a mesh CA read over plaintext http was accepted")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("refusal does not name the scheme: %v", err)
	}
}

// A URL that does not parse is a typo, not a plaintext endpoint; reporting it
// as one sends an operator looking for a scheme they did not write.
func TestRefusesAnUnparseableURLWithoutBlamingTheScheme(t *testing.T) {
	_, _, err := run(t, "--url", "://missing-scheme", "--measurements", testMeasurement)
	if err == nil {
		t.Fatal("an unparseable --url was accepted")
	}
	if !strings.Contains(err.Error(), "://missing-scheme") {
		t.Fatalf("refusal does not quote the url given: %v", err)
	}
	if strings.Contains(err.Error(), "https") {
		t.Fatalf("an unparseable url was reported as a scheme problem: %v", err)
	}
}

// The bytes written are the DER the --mesh-ca gate compares, in the order CDS
// serves them (newest CA first, retained CAs after), and every certificate's
// digest is reported so an operator can pin it out of band.
func TestWritesTheServedChainAndReportsEachDigest(t *testing.T) {
	newest, retained := meshCA(t, "cds-m-2"), meshCA(t, "cds-m-1")
	_, url := newAttestedCDS(t, http.StatusOK, servingPEM(newest, retained))
	out := filepath.Join(t.TempDir(), "mesh-ca.pem")

	_, stderr, err := run(t, "--url", url, "--measurements", testMeasurement, "--out", out)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	written := parsePEM(t, readFile(t, out))
	if len(written) != 2 {
		t.Fatalf("wrote %d certificate(s), want the 2 CDS served", len(written))
	}
	for i, want := range [][]byte{newest, retained} {
		if !bytes.Equal(written[i].Raw, want) {
			t.Fatalf("certificate %d is not the DER CDS served", i)
		}
		sum := sha256.Sum256(want)
		if !strings.Contains(stderr, hex.EncodeToString(sum[:])) {
			t.Fatalf("certificate %d's digest was not reported: %q", i, stderr)
		}
	}
}

// With no --out the bundle goes to stdout, so it pipes into the flags that take
// it without an intermediate file, while the digests stay on stderr.
func TestWritesToStdoutWithoutOut(t *testing.T) {
	ca := meshCA(t, "cds-m")
	_, url := newAttestedCDS(t, http.StatusOK, servingPEM(ca))

	stdout, _, err := run(t, "--url", url, "--measurements", testMeasurement)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	written := parsePEM(t, []byte(stdout))
	if len(written) != 1 || !bytes.Equal(written[0].Raw, ca) {
		t.Fatalf("stdout is not the served certificate: %q", stdout)
	}
}

// The anchor file holds certificates and nothing else: whatever else an
// endpoint puts in the response does not become part of what an operator pins.
func TestDropsNonCertificateBlocks(t *testing.T) {
	ca := meshCA(t, "cds-m")
	body := append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("filler")}), servingPEM(ca)...)
	_, url := newAttestedCDS(t, http.StatusOK, body)
	out := filepath.Join(t.TempDir(), "mesh-ca.pem")

	if _, _, err := run(t, "--url", url, "--measurements", testMeasurement, "--out", out); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if got := readFile(t, out); !bytes.Equal(got, servingPEM(ca)) {
		t.Fatalf("the bundle carries more than the served certificate: %q", got)
	}
}

// A body that is not a certificate bundle must not reach an anchor file: an
// endpoint answering /ca with anything else is the wrong endpoint.
func TestRefusesANonCertificateBody(t *testing.T) {
	_, url := newAttestedCDS(t, http.StatusOK, []byte("not a bundle"))
	out := filepath.Join(t.TempDir(), "mesh-ca.pem")

	if _, _, err := run(t, "--url", url, "--measurements", testMeasurement, "--out", out); err == nil {
		t.Fatal("a body with no CERTIFICATE block was accepted")
	}
	assertNotWritten(t, out)
}

// A front door that does not proxy /ca answers 404; nothing lands at --out, so
// a path already holding an anchor still holds it.
func TestRefusesANonOKResponse(t *testing.T) {
	_, url := newAttestedCDS(t, http.StatusNotFound, []byte("no such route"))
	out := filepath.Join(t.TempDir(), "mesh-ca.pem")

	_, _, err := run(t, "--url", url, "--measurements", testMeasurement, "--out", out)
	if err == nil {
		t.Fatal("a 404 at /ca was accepted")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error does not name the status: %v", err)
	}
	assertNotWritten(t, out)
}

func parsePEM(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	certs, err := certutil.ParsePEMCertificates(b)
	if err != nil {
		t.Fatalf("parse written bundle: %v", err)
	}
	return certs
}

func assertNotWritten(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s was written by a failed read", path)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestImagePolicyGatesCARead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		digest string
		accept bool
	}{
		{"matching image", testMeasurement, true},
		{"different image", strings.Repeat("ab", 48), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := meshCA(t, "cds-m")
			seen, url := newAttestedCDS(t, http.StatusOK, servingPEM(ca))
			policy := filepath.Join(t.TempDir(), "policy.json")
			data := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + tc.digest + `"}]}`
			if err := os.WriteFile(policy, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			stdout, _, err := run(t, "--url", url, "--image-policy-file", policy)
			if !tc.accept {
				if err == nil || !strings.Contains(err.Error(), "endpoint identity") {
					t.Fatalf("expected endpoint identity rejection, got %v", err)
				}
				if *seen != 0 || stdout != "" {
					t.Fatalf("rejected image exposed a CA: requests=%d output=%q", *seen, stdout)
				}
				return
			}
			if err != nil {
				t.Fatalf("read with matching image policy: %v", err)
			}
			if *seen != 1 || stdout != string(servingPEM(ca)) {
				t.Fatalf("matching image did not return the served CA: requests=%d output=%q", *seen, stdout)
			}
		})
	}
}
