package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// testMeasurement is a syntactically valid SHA-384 launch measurement. Its
// value is irrelevant: the injected verifier approves, so what these tests
// exercise is the mesh-CA gate that runs after a pinned measurement passes.
const testMeasurement = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// meshCA mints a self-signed CA certificate standing in for one CDS's mesh CA.
// Two calls produce two distinct CAs — the CDS_M / CDS_N split this gate exists
// to detect.
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

func writePEM(t *testing.T, name string, ders ...[]byte) string {
	t.Helper()
	var buf bytes.Buffer
	for _, der := range ders {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// armtlsServingCert mints the self-signed ARmTLS serving cert a direct CDS
// presents, so the CLI reaches the write over the same attested path it uses in
// production rather than over plaintext.
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
	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: embedded}
	ext, err := armtls.MarshalExtension(att)
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

// newAttestedCDS serves the secrets API over ARmTLS, answering GET /ca with
// caDER. Returns the fake and its https URL.
func newAttestedCDS(t *testing.T, caDER []byte) (*fakeCDS, string) {
	t.Helper()
	var body []byte
	if caDER != nil {
		body = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	}
	return newAttestedCDSServingCA(t, http.StatusOK, body)
}

// newAttestedCDSServingCA is newAttestedCDS with the /ca response written out
// verbatim, for the answers a well-behaved CDS never gives.
func newAttestedCDSServingCA(t *testing.T, status int, body []byte) (*fakeCDS, string) {
	t.Helper()
	f := &fakeCDS{values: map[string]intsecrets.Origin{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/", f.serve)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{armtlsServingCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return f, srv.URL
}

// runAttested drives the CLI with an attestation verifier that approves, so the
// only thing under test is the mesh-CA gate.
func runAttested(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	approve := func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		match := true
		return &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &match}, nil
	}
	cmd := newCmd(testutil.VerifierStub(approve))
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

// A measurement pin proves the peer is an attested build; every confidential
// pod boots that build, so the write is refused until the operator names the
// mesh CA that distinguishes their CDS from anything else at the same shape.
func TestPutRefusesWithoutMeshCA(t *testing.T) {
	f, url := newAttestedCDS(t, meshCA(t, "cds-m"))
	key := writeOperatorKey(t)

	_, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key)
	if err == nil {
		t.Fatal("a write with no --mesh-ca was accepted")
	}
	if !strings.Contains(err.Error(), "--mesh-ca") {
		t.Fatalf("refusal does not name --mesh-ca: %v", err)
	}
	if len(f.seen) != 0 {
		t.Fatalf("the refused write still sent %d request(s)", len(f.seen))
	}
}

// The gate is an identity check on the CA key, so a CDS serving a CA the
// operator never pinned is refused even though its attestation is valid — the
// CDS_N case, where a genuine TEE at the same measurement is not your CDS.
func TestPutRefusesAnotherCDSsMeshCA(t *testing.T) {
	f, url := newAttestedCDS(t, meshCA(t, "cds-n"))
	bundle := writePEM(t, "mesh-ca.pem", meshCA(t, "cds-m"))
	key := writeOperatorKey(t)

	_, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", bundle)
	if err == nil {
		t.Fatal("a write to a CDS serving an unpinned mesh CA was accepted")
	}
	if !strings.Contains(err.Error(), "not in --mesh-ca") {
		t.Fatalf("refusal does not name the mismatch: %v", err)
	}
	if len(f.seen) != 0 {
		t.Fatalf("the refused write still sent %d request(s)", len(f.seen))
	}
}

// The matching CA is the whole point: the write proceeds and the secret lands.
func TestPutAcceptsThePinnedMeshCA(t *testing.T) {
	ca := meshCA(t, "cds-m")
	f, url := newAttestedCDS(t, ca)
	bundle := writePEM(t, "mesh-ca.pem", ca)
	key := writeOperatorKey(t)

	out, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", bundle)
	if err != nil {
		t.Fatalf("put against the pinned CDS: %v", err)
	}
	if !strings.Contains(out, "+ /tenant-a/db (new)") {
		t.Fatalf("output = %q", out)
	}
	if len(f.seen) != 1 {
		t.Fatalf("sent %d requests, want 1", len(f.seen))
	}
}

// A bundle carrying several CAs (rotation) admits a CDS serving any one of
// them, and still refuses one serving a CA outside the bundle.
func TestPutAcceptsAnyCAInTheBundle(t *testing.T) {
	old, current := meshCA(t, "cds-old"), meshCA(t, "cds-current")
	bundle := writePEM(t, "mesh-ca.pem", old, current)
	key := writeOperatorKey(t)

	for _, ca := range [][]byte{old, current} {
		_, url := newAttestedCDS(t, ca)
		if _, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
			"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", bundle); err != nil {
			t.Fatalf("a CA in the bundle was refused: %v", err)
		}
	}
	_, url := newAttestedCDS(t, meshCA(t, "cds-n"))
	if _, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", bundle); err == nil {
		t.Fatal("a CA outside the bundle was accepted")
	}
}

// --force is the documented escape hatch. It writes, and it says on stderr that
// it skipped the check, so the bypass is visible in an operator's transcript.
func TestPutForceSkipsTheCheckLoudly(t *testing.T) {
	f, url := newAttestedCDS(t, meshCA(t, "cds-n"))
	key := writeOperatorKey(t)

	_, errOut, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key, "--force")
	if err != nil {
		t.Fatalf("--force did not write: %v", err)
	}
	if !strings.Contains(errOut, "--force") || !strings.Contains(errOut, "without checking the CDS mesh CA") {
		t.Fatalf("--force wrote without announcing the skipped check: %q", errOut)
	}
	if len(f.seen) != 1 {
		t.Fatalf("sent %d requests, want 1", len(f.seen))
	}
}

// CDS answering /ca with nothing must not read as a match: an empty served set
// would vacuously satisfy a subset check.
func TestPutRefusesEmptyServedCA(t *testing.T) {
	_, url := newAttestedCDS(t, nil)
	bundle := writePEM(t, "mesh-ca.pem", meshCA(t, "cds-m"))
	key := writeOperatorKey(t)

	_, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", bundle)
	if err == nil {
		t.Fatal("a CDS serving no CA was accepted")
	}
	if !strings.Contains(err.Error(), "served no certificate") {
		t.Fatalf("err = %v", err)
	}
}

// An unreadable or certificate-free bundle fails the write rather than
// degrading to no check.
func TestPutRefusesUnusableBundle(t *testing.T) {
	_, url := newAttestedCDS(t, meshCA(t, "cds-m"))
	key := writeOperatorKey(t)
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"absent":   filepath.Join(t.TempDir(), "nope.pem"),
		"no certs": empty,
	} {
		_, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
			"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", path)
		if err == nil {
			t.Fatalf("%s bundle was accepted", name)
		}
	}
}

// The dev path is exempt for the same reason it is exempt from the measurement
// pin: --insecure has already said nothing about the peer is authenticated.
func TestPutPlaintextInsecureSkipsTheGate(t *testing.T) {
	f, url := newFakeCDS(t)
	key := writeOperatorKey(t)

	if _, _, err := run(t, "hunter2", "put", "/tenant-a/db", "--url", url, "--insecure", "--operator-key", key); err != nil {
		t.Fatalf("plaintext dev write refused: %v", err)
	}
	if len(f.seen) != 1 {
		t.Fatalf("sent %d requests, want 1", len(f.seen))
	}
}

// An answer that is not a served CA must fail the write rather than be read as
// one. Each of these is a distinct refusal, and none of them may fall through
// to a comparison against a set the CLI never actually received.
func TestPutRefusesAnUnusableCAResponse(t *testing.T) {
	good := meshCA(t, "cds-m")
	bundle := writePEM(t, "mesh-ca.pem", good)
	key := writeOperatorKey(t)

	tests := []struct {
		name   string
		status int
		body   []byte
		want   string
	}{
		{
			// A CDS that does not route /ca (an LB pointed elsewhere, or a
			// build without the route) must not read as "no CA to object to".
			name:   "not found",
			status: http.StatusNotFound,
			body:   []byte("no such route\n"),
			want:   "returned 404",
		},
		{
			name:   "server error",
			status: http.StatusInternalServerError,
			body:   []byte("boom\n"),
			want:   "returned 500",
		},
		{
			// Truncated DER inside a well-formed PEM frame: the block decodes,
			// the certificate does not. Skipping it would leave the served set
			// empty and the comparison vacuous.
			name:   "certificate does not parse",
			status: http.StatusOK,
			body:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: good[:len(good)/2]}),
			want:   "does not parse",
		},
		{
			// PEM that carries no certificate at all.
			name:   "no certificate block",
			status: http.StatusOK,
			body:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}),
			want:   "served no certificate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, url := newAttestedCDSServingCA(t, tc.status, tc.body)
			_, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
				"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", bundle)
			if err == nil {
				t.Fatal("the write was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to name %q", err, tc.want)
			}
			if len(f.seen) != 0 {
				t.Fatalf("the refused write still sent %d request(s)", len(f.seen))
			}
		})
	}
}

// A CDS whose /ca is unreachable fails the write. The gate has no "could not
// check, so proceed" branch: an unanswered /ca is the same refusal as a wrong
// one.
func TestPutRefusesWhenTheCAIsUnreachable(t *testing.T) {
	_, url := newAttestedCDS(t, meshCA(t, "cds-m"))
	bundle := writePEM(t, "mesh-ca.pem", meshCA(t, "cds-m"))
	key := writeOperatorKey(t)

	// A port with nothing behind it: the URL parses and the scheme is https,
	// so the gate runs and the fetch is what fails.
	dead := strings.Replace(url, url[strings.LastIndex(url, ":")+1:], "1", 1)
	_, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", dead,
		"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", bundle)
	if err == nil {
		t.Fatal("a write to an unreachable CDS was accepted")
	}
}

// A bundle carrying a non-certificate PEM block alongside the CA is still a
// usable bundle: the extra block is skipped, and the CA in it still matches.
// Operators paste these out of files that hold more than one kind of object.
func TestPutIgnoresNonCertificateBlocksInTheBundle(t *testing.T) {
	ca := meshCA(t, "cds-m")
	f, url := newAttestedCDS(t, ca)
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mixed.pem")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	key := writeOperatorKey(t)

	if _, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", path); err != nil {
		t.Fatalf("a bundle with a non-certificate block was refused: %v", err)
	}
	if len(f.seen) != 1 {
		t.Fatalf("sent %d requests, want 1", len(f.seen))
	}
}

// A bundle whose certificate does not parse fails the write. Pinning against a
// set the CLI could not fully read is not pinning.
func TestPutRefusesABundleWithAnUnparseableCertificate(t *testing.T) {
	ca := meshCA(t, "cds-m")
	_, url := newAttestedCDS(t, ca)
	path := filepath.Join(t.TempDir(), "truncated.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca[:len(ca)/2]}), 0o600); err != nil {
		t.Fatal(err)
	}
	key := writeOperatorKey(t)

	_, _, err := runAttested(t, "hunter2", "put", "/tenant-a/db", "--url", url,
		"--measurements", testMeasurement, "--operator-key", key, "--mesh-ca", path)
	if err == nil {
		t.Fatal("an unparseable bundle was accepted")
	}
	if !strings.Contains(err.Error(), "--mesh-ca") || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("err = %v", err)
	}
}
