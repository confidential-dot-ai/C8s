package cdsconn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestValidateRequiresURL(t *testing.T) {
	var o Options
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "--url is required") {
		t.Fatalf("expected a --url error, got %v", err)
	}
	o.URL = "  "
	if err := o.Validate(); err == nil {
		t.Fatal("whitespace-only --url was accepted")
	}
	o.URL = "https://cds.example"
	if err := o.Validate(); err != nil {
		t.Fatalf("a real --url was rejected: %v", err)
	}
}

// Plaintext http reaches an endpoint that has proved nothing, so it needs
// --insecure. This is the gate both operator CLIs depend on.
func TestHTTPClientRefusesPlaintextWithoutInsecure(t *testing.T) {
	o := Options{URL: "http://cds.example:8080"}
	if _, err := o.HTTPClient(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing plaintext") {
		t.Fatalf("expected a plaintext refusal, got %v", err)
	}

	o.Insecure = true
	if _, err := o.HTTPClient(context.Background()); err != nil {
		t.Fatalf("--insecure should allow http, got %v", err)
	}
}

// A target that serves no discovery document is a direct CDS URL, which is
// verified by armTLS on its serving certificate rather than through a front
// door. Nothing is dialled until a request is made, so the fallback yields a
// client rather than an error.
func TestHTTPClientFallsBackToARMTLS(t *testing.T) {
	o := Options{
		URL:     "https://" + closedAddr(t),
		Timeout: time.Second,
		Verifier: testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
			return nil, nil
		}),
	}
	hc, err := o.HTTPClient(context.Background())
	if err != nil {
		t.Fatalf("HTTPClient: %v", err)
	}
	if hc.Timeout != time.Second {
		t.Fatalf("Timeout = %s, want the --timeout value", hc.Timeout)
	}
}

// closedAddr returns a host:port nothing is listening on.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestHTTPClientRejectsBadURL(t *testing.T) {
	for _, tc := range []struct{ name, url, want string }{
		{"no host", "https://", "invalid --url"},
		{"unknown scheme", "ftp://cds.example", "scheme must be http or https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{URL: tc.url}
			_, err := o.HTTPClient(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadMeasurementsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "measurements.txt")
	m1 := strings.Repeat("42", armtls.SNPMeasurementSize)
	m2 := strings.Repeat("ab", armtls.SNPMeasurementSize)
	// blank lines and surrounding whitespace must be tolerated
	if err := os.WriteFile(path, []byte(m1+"\n\n  "+m2+"  \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	o := Options{MeasurementsFile: path}
	got, err := o.loadMeasurements()
	if err != nil {
		t.Fatalf("loadMeasurements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 measurements, got %d", len(got))
	}
}

func TestLoadMeasurementsCombinesFlagAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "measurements.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("ab", armtls.SNPMeasurementSize)+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	o := Options{
		Measurements:     []string{strings.Repeat("42", armtls.SNPMeasurementSize)},
		MeasurementsFile: path,
	}
	got, err := o.loadMeasurements()
	if err != nil {
		t.Fatalf("loadMeasurements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected flag+file to combine into 2 measurements, got %d", len(got))
	}
}

func TestLoadMeasurementsFileMissing(t *testing.T) {
	o := Options{MeasurementsFile: filepath.Join(t.TempDir(), "nope.txt")}
	if _, err := o.loadMeasurements(); err == nil || !strings.Contains(err.Error(), "read --measurements-file") {
		t.Fatalf("expected a read error, got %v", err)
	}
}

func TestLoadMeasurementsRejectsBadHex(t *testing.T) {
	o := Options{Measurements: []string{"not-hex"}}
	if _, err := o.loadMeasurements(); err == nil {
		t.Fatal("expected invalid hex to be rejected")
	}
}

func TestSignerRequiresAKey(t *testing.T) {
	t.Setenv(EnvOperatorKey, "")
	var o Options
	if _, err := o.Signer(); err == nil || !strings.Contains(err.Error(), "operator key required") {
		t.Fatalf("expected a missing-key error, got %v", err)
	}
}

// The env var is the fallback so an operator does not repeat the path on every
// write; the flag wins when both are set.
func TestSignerReadsTheEnvAndPrefersTheFlag(t *testing.T) {
	key := writeTestKey(t)
	t.Setenv(EnvOperatorKey, key)

	o := Options{Measurements: []string{"abababababababababababababababababababababababababababababababababababababababababababababababab"}}
	if _, err := o.Signer(); err != nil {
		t.Fatalf("env fallback: %v", err)
	}
	o.OperatorKey = filepath.Join(t.TempDir(), "nonexistent.key")
	if _, err := o.Signer(); err == nil {
		t.Fatal("the flag did not take precedence over the env var")
	}
}

func writeTestKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "operator.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSignerMissingKeyFile(t *testing.T) {
	o := Options{OperatorKey: filepath.Join(t.TempDir(), "nope.key")}
	if _, err := o.Signer(); err == nil || !strings.Contains(err.Error(), "read operator key") {
		t.Fatalf("expected a read error, got %v", err)
	}
}

func TestSignerRejectsGarbagePEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	o := Options{OperatorKey: path, Measurements: []string{"abababababababababababababababababababababababababababababababababababababababababababababababab"}}
	if _, err := o.Signer(); err == nil || !strings.Contains(err.Error(), "load operator key") {
		t.Fatalf("expected a key-parse error, got %v", err)
	}
}

// Both operator CLIs bind these, so the names are part of the interface.
func TestBindFlagsNamesEveryOption(t *testing.T) {
	var o Options
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	BindFlags(fs, &o)
	for _, name := range []string{"url", "measurements", "measurements-file", "image-policy-file", "timeout", "operator-key", "insecure"} {
		if fs.Lookup(name) == nil {
			t.Errorf("--%s is not bound", name)
		}
	}
	if fs.Lookup("measurements-config") != nil {
		t.Fatal("removed --measurements-config alias is still bound")
	}
	if err := fs.Parse([]string{"--url", "https://cds.example", "--operator-key", "/k.pem", "--image-policy-file", "policy.json"}); err != nil {
		t.Fatal(err)
	}
	if o.URL != "https://cds.example" || o.OperatorKey != "/k.pem" || o.MeasurementsConfig != "policy.json" {
		t.Fatalf("parsed into %+v", o)
	}
}

// An https CDS with no --measurements is attested but not identified: armTLS
// proves the peer is a TEE, not that it is the CDS this operator meant. Reads
// only warn, but a signed token hands `c8s secrets put`'s secret and
// `c8s allowlist`'s policy change to whatever answered, so minting one is
// refused outright.
func TestSignerRefusesAnUnpinnedEndpoint(t *testing.T) {
	key := writeTestKey(t)

	o := Options{URL: "https://cds.example:8443", OperatorKey: key}
	_, err := o.Signer()
	if err == nil || !strings.Contains(err.Error(), "unpinned CDS") {
		t.Fatalf("err = %v, want a refusal naming the unpinned CDS", err)
	}
	if !strings.Contains(err.Error(), "--measurements") {
		t.Errorf("the refusal must name the flag that fixes it, got %q", err)
	}

	// Pinned by either flag.
	o.Measurements = []string{strings.Repeat("ab", 48)}
	if _, err := o.Signer(); err != nil {
		t.Fatalf("--measurements should satisfy the pin, got %v", err)
	}
	o.Measurements = nil
	o.MeasurementsFile = writeMeasurementsFile(t, strings.Repeat("cd", 48))
	if _, err := o.Signer(); err != nil {
		t.Fatalf("--measurements-file should satisfy the pin, got %v", err)
	}

	// Plaintext is HTTPClient's call, not this gate's: without --insecure it is
	// refused there, and that error is the specific one.
	o.MeasurementsFile = ""
	o.URL = "http://cds.example:8080"
	if _, err := o.Signer(); err != nil {
		t.Fatalf("plaintext must fall through to the HTTPClient refusal, got %v", err)
	}
}

func writeMeasurementsFile(t *testing.T, hexes ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "measurements.txt")
	if err := os.WriteFile(p, []byte(strings.Join(hexes, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write measurements file: %v", err)
	}
	return p
}
