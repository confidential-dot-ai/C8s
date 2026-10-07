package getcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestCDSHTTPClientRejectsPlainHTTP(t *testing.T) {
	// A non-https --cds-url must be refused, not quietly served over a client
	// that skips armTLS attestation of CDS.
	for _, scheme := range []string{"http://cds:8443", "cds:8443", "tcp://cds:8443"} {
		if _, err := cdsHTTPClient(config{CDSURL: scheme, AttestationApiURL: "http://attestation-api:8400"}); err == nil {
			t.Fatalf("cdsHTTPClient(%q) succeeded, want error for non-https scheme", scheme)
		}
	}
}

func TestCDSHTTPClientUsesARMTLSForHTTPS(t *testing.T) {
	client, err := cdsHTTPClient(config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
	})
	if err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
	if client == http.DefaultClient {
		t.Fatal("client = http.DefaultClient, want armTLS client")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLSClientConfig.InsecureSkipVerify = false, want armTLS verification path")
	}
}

func TestBuildDiscoveryDocumentIncludesCertificateAndEvidence(t *testing.T) {
	certPEM := testCertificatePEM(t)
	result := attestclient.CertificateResult{
		Certificate: certPEM,
		Challenge:   "dGVzdC1jaGFsbGVuZ2U=",
		Platform:    "snp",
		Evidence:    json.RawMessage(`{"quote":"abc"}`),
	}

	doc, err := buildDiscoveryDocument(config{
		SAN:                    "confidential-gke.confidential.ai",
		DiscoveryCDSCertURL:    "/.well-known/cds-cert.pem",
		DiscoveryMeshCAURL:     "/.well-known/mesh-ca.pem",
		DiscoveryPublicTLSMode: "webpki",
	}, result)
	if err != nil {
		t.Fatalf("buildDiscoveryDocument: %v", err)
	}

	if doc.Version != "v1" {
		t.Fatalf("version = %q, want v1", doc.Version)
	}
	if doc.PublicTLS.Hostname != "confidential-gke.confidential.ai" {
		t.Fatalf("hostname = %q", doc.PublicTLS.Hostname)
	}
	if doc.PublicTLS.Mode != "webpki" {
		t.Fatalf("public tls mode = %q, want webpki", doc.PublicTLS.Mode)
	}
	if doc.CDSTLS.CertificatePEM != certPEM {
		t.Fatal("CDS certificate PEM not preserved")
	}
	if len(doc.CDSTLS.CertificateSHA256) != 64 {
		t.Fatalf("certificate sha256 = %q, want 64 hex chars", doc.CDSTLS.CertificateSHA256)
	}
	if doc.CDSTLS.CertificateURL != "/.well-known/cds-cert.pem" {
		t.Fatalf("certificate URL = %q", doc.CDSTLS.CertificateURL)
	}
	if doc.CDSTLS.MeshCAURL != "/.well-known/mesh-ca.pem" {
		t.Fatalf("mesh CA URL = %q", doc.CDSTLS.MeshCAURL)
	}
	if doc.Attestation.Challenge != result.Challenge {
		t.Fatalf("challenge = %q", doc.Attestation.Challenge)
	}
	if doc.Attestation.Platform != "snp" {
		t.Fatalf("platform = %q", doc.Attestation.Platform)
	}
	if !strings.Contains(string(doc.Attestation.Evidence), `"quote":"abc"`) {
		t.Fatalf("evidence = %s", doc.Attestation.Evidence)
	}
}

func TestValidateConfigRejectsInvalidDiscoveryPublicTLSMode(t *testing.T) {
	err := validateConfig(config{
		CDSURL:                 "http://cds:8443",
		AttestationApiURL:      "http://attestation-api:8400",
		SAN:                    "confidential-gke.confidential.ai",
		DiscoveryOutPath:       "/tmp/discovery.json",
		DiscoveryPublicTLSMode: "invalid",
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want invalid discovery public TLS mode error")
	}
	if !errors.Is(err, errInvalidDiscoveryPublicTLSMode) {
		t.Fatalf("error = %v, want discovery public TLS mode error", err)
	}
}

func TestValidateConfigRejectsInvalidReloadWatchInterval(t *testing.T) {
	err := validateConfig(config{
		CDSURL:            "http://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "confidential-gke.confidential.ai",
		ReloadWatchPaths:  []string{"/public-tls/tls.crt"},
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want reload watch interval error")
	}
	if !errors.Is(err, errInvalidReloadWatchInterval) {
		t.Fatalf("error = %v, want reload watch interval error", err)
	}
}

func TestValidateConfigRejectsReloadWatchWithoutRenewInterval(t *testing.T) {
	err := validateConfig(config{
		CDSURL:              "http://cds:8443",
		AttestationApiURL:   "http://attestation-api:8400",
		SAN:                 "confidential-gke.confidential.ai",
		ReloadWatchPaths:    []string{"/public-tls/tls.crt"},
		ReloadWatchInterval: time.Minute,
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want reload watch renew interval error")
	}
	if !errors.Is(err, errReloadWatchRequiresRenewInterval) {
		t.Fatalf("error = %v, want renew interval error", err)
	}
}

func TestValidateConfigRejectsContinueOnInitialErrorWithoutRenewInterval(t *testing.T) {
	err := validateConfig(config{
		CDSURL:                 "http://cds:8443",
		AttestationApiURL:      "http://attestation-api:8400",
		SAN:                    "confidential-gke.confidential.ai",
		ContinueOnInitialError: true,
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want continue-on-initial-error renew interval error")
	}
	if !errors.Is(err, errContinueOnInitialErrorRequiresRenewalLoop) {
		t.Fatalf("error = %v, want continue-on-initial-error error", err)
	}
}

// --key-out reuses an existing key at the path instead of overwriting it.
// This is what makes a single long-running cert sidecar safe across
// container restarts — a fresh key would invalidate any cert CDS has
// already issued for the previous key.
func TestLoadOrGenerateKeyReusesExistingKeyOutFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.key")

	first, firstPEM, err := loadOrGenerateKey(config{KeyOutPath: path})
	if err != nil {
		t.Fatalf("loadOrGenerateKey(initial): %v", err)
	}
	if err := fileutil.WriteAtomic(path, firstPEM, 0600); err != nil {
		t.Fatal(err)
	}

	second, _, err := loadOrGenerateKey(config{KeyOutPath: path})
	if err != nil {
		t.Fatalf("loadOrGenerateKey(reuse): %v", err)
	}
	if !first.Equal(second) {
		t.Fatal("loadOrGenerateKey returned a different key on the second call; key-out must be reused once written")
	}
}

func TestLoadOrGenerateKeyGeneratesWhenKeyOutFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.key")
	key, pem, err := loadOrGenerateKey(config{KeyOutPath: path})
	if err != nil {
		t.Fatalf("loadOrGenerateKey: %v", err)
	}
	if key == nil || len(pem) == 0 {
		t.Fatal("expected freshly generated key + PEM")
	}
}

func TestWriteFileAtomicReplacesFileAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := fileutil.WriteAtomic(path, []byte("new"), 0644); err != nil {
		t.Fatalf("fileutil.WriteAtomic: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("data = %q, want new", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Fatalf("mode = %#o, want 0644", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".cert.pem.tmp-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestReloadWatchChangedDetectsFileReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	previous, err := snapshotReloadWatchPaths([]string{path})
	if err != nil {
		t.Fatalf("snapshotReloadWatchPaths: %v", err)
	}

	if err := fileutil.WriteAtomic(path, []byte("new certificate"), 0644); err != nil {
		t.Fatalf("fileutil.WriteAtomic: %v", err)
	}
	changed, next, err := reloadWatchChanged(previous, []string{path})
	if err != nil {
		t.Fatalf("reloadWatchChanged: %v", err)
	}
	if !changed {
		t.Fatal("reloadWatchChanged = false, want true")
	}

	changed, _, err = reloadWatchChanged(next, []string{path})
	if err != nil {
		t.Fatalf("reloadWatchChanged second check: %v", err)
	}
	if changed {
		t.Fatal("reloadWatchChanged detected change without file mutation")
	}
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"confidential-gke.confidential.ai"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCABundleFromChain(t *testing.T) {
	// caBundleFromChain splits by PEM block, so synthetic CERTIFICATE blocks
	// with arbitrary bytes exercise the logic without minting real certs.
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("leaf")}))
	ca1 := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("ca-one")}))
	ca2 := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("ca-two")}))

	t.Run("drops the leaf, returns one CA", func(t *testing.T) {
		got, err := caBundleFromChain([]byte(leaf + ca1))
		if err != nil {
			t.Fatalf("caBundleFromChain: %v", err)
		}
		if string(got) != ca1 {
			t.Fatalf("bundle = %q, want %q", got, ca1)
		}
	})

	t.Run("returns all issuers after the leaf", func(t *testing.T) {
		got, err := caBundleFromChain([]byte(leaf + ca1 + ca2))
		if err != nil {
			t.Fatalf("caBundleFromChain: %v", err)
		}
		if string(got) != ca1+ca2 {
			t.Fatalf("bundle = %q, want %q", got, ca1+ca2)
		}
	})

	t.Run("errors when only the leaf is present", func(t *testing.T) {
		if _, err := caBundleFromChain([]byte(leaf)); err == nil {
			t.Fatal("expected error for a leaf-only chain, got nil")
		}
	})
}

// plaintextCDSClient builds an attestclient over the default transport for
// tests that drive the cert flow against a plaintext httptest CDS. Production
// requires https (see cdsHTTPClient), so these tests inject the client
// directly rather than route through newCDSClient.
func plaintextCDSClient(cdsURL string) attestclient.Client {
	return attestclient.NewClientWithHTTP(cdsURL, http.DefaultClient)
}

func TestValidateConfigAccepts(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
	}{
		{
			name: "minimal",
			cfg: config{
				CDSURL:            "http://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
				SAN:               "confidential-gke.confidential.ai",
			},
		},
		{
			name: "ip san",
			cfg: config{
				CDSURL:            "https://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
				SAN:               "10.0.0.1",
			},
		},
		{
			name: "reload watch with renew",
			cfg: config{
				CDSURL:              "http://cds:8443",
				AttestationApiURL:   "http://attestation-api:8400",
				SAN:                 "host.example.com",
				ReloadWatchPaths:    []string{"/tls.crt"},
				ReloadWatchInterval: time.Minute,
				RenewInterval:       time.Hour,
			},
		},
		{
			name: "continue on initial error with renew",
			cfg: config{
				CDSURL:                 "http://cds:8443",
				AttestationApiURL:      "http://attestation-api:8400",
				SAN:                    "host.example.com",
				ContinueOnInitialError: true,
				RenewInterval:          time.Hour,
			},
		},
		{
			name: "discovery webpki",
			cfg: config{
				CDSURL:                 "http://cds:8443",
				AttestationApiURL:      "http://attestation-api:8400",
				SAN:                    "host.example.com",
				DiscoveryOutPath:       "/tmp/d.json",
				DiscoveryPublicTLSMode: "webpki",
			},
		},
		{
			name: "ca watch with ca-out and renew",
			cfg: config{
				CDSURL:            "http://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
				SAN:               "host.example.com",
				CAOutPath:         "/tls/ca.pem",
				RenewInterval:     time.Hour,
				CAWatchInterval:   time.Minute,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateConfig(tt.cfg); err != nil {
				t.Fatalf("validateConfig: %v", err)
			}
		})
	}
}

func TestValidateConfigRejects(t *testing.T) {
	base := config{
		CDSURL:            "http://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	tests := []struct {
		name   string
		mutate func(*config)
	}{
		{"empty cds url", func(c *config) { c.CDSURL = "" }},
		{"bad cds url", func(c *config) { c.CDSURL = "://nope" }},
		{"empty attestation url", func(c *config) { c.AttestationApiURL = "" }},
		{"empty san", func(c *config) { c.SAN = "" }},
		{"url san", func(c *config) { c.SAN = "https://host.example.com" }},
		{"negative ca watch interval", func(c *config) {
			c.CAOutPath = "/tls/ca.pem"
			c.RenewInterval = time.Hour
			c.CAWatchInterval = -time.Minute
		}},
		{"ca watch without ca-out", func(c *config) {
			c.RenewInterval = time.Hour
			c.CAWatchInterval = time.Minute
		}},
		{"ca watch without renew interval", func(c *config) {
			c.CAOutPath = "/tls/ca.pem"
			c.CAWatchInterval = time.Minute
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if err := validateConfig(cfg); err == nil {
				t.Fatal("validateConfig succeeded, want error")
			}
		})
	}
}

func TestValidateSAN(t *testing.T) {
	tests := []struct {
		name    string
		san     string
		wantErr bool
	}{
		{"ipv4", "192.168.1.1", false},
		{"ipv6", "::1", false},
		{"hostname", "host.example.com", false},
		{"single label", "host", false},
		{"empty", "", true},
		{"http url", "http://host", true},
		{"https url", "https://host", true},
		{"wildcard", "*.example.com", true},
		{"trailing dot label", "host..com", true},
		{"max length", strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 61), false},
		{"too long", strings.Repeat("a", 254), true},
		{"label too long", strings.Repeat("a", 64) + ".com", true},
		{"underscore", "host_name.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSAN(tt.san)
			if tt.wantErr != (err != nil) {
				t.Fatalf("validateSAN(%q) err = %v, wantErr = %v", tt.san, err, tt.wantErr)
			}
		})
	}
}

func TestDiscoveryPublicTLSMode(t *testing.T) {
	if got := discoveryPublicTLSMode(""); got != "cds" {
		t.Fatalf("empty = %q, want cds", got)
	}
	if got := discoveryPublicTLSMode("webpki"); got != "webpki" {
		t.Fatalf("webpki = %q, want webpki", got)
	}
}

func TestValidateOutputPaths(t *testing.T) {
	dir := t.TempDir()

	t.Run("empty paths skipped", func(t *testing.T) {
		if err := validateOutputPaths("", "", ""); err != nil {
			t.Fatalf("validateOutputPaths: %v", err)
		}
	})

	t.Run("writable dir ok", func(t *testing.T) {
		if err := validateOutputPaths(filepath.Join(dir, "cert.pem")); err != nil {
			t.Fatalf("validateOutputPaths: %v", err)
		}
	})

	t.Run("missing dir", func(t *testing.T) {
		if err := validateOutputPaths(filepath.Join(dir, "missing", "cert.pem")); err == nil {
			t.Fatal("validateOutputPaths succeeded, want error for missing dir")
		}
	})

	t.Run("parent is a file", func(t *testing.T) {
		f := filepath.Join(dir, "afile")
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validateOutputPaths(filepath.Join(f, "cert.pem")); err == nil {
			t.Fatal("validateOutputPaths succeeded, want error for file parent")
		}
	})
}

// TestRequireKeyOutRAMBacked: the private key's memory-only invariant is
// enforced, not merely documented.
func TestRequireKeyOutRAMBacked(t *testing.T) {
	t.Run("empty key-out exempt", func(t *testing.T) {
		if err := requireKeyOutRAMBacked(""); err != nil {
			t.Fatalf("requireKeyOutRAMBacked(\"\"): %v", err)
		}
	})

	t.Run("persistent storage refused", func(t *testing.T) {
		dir := t.TempDir()
		if fileutil.RequireRAMBacked(dir) == nil {
			t.Skipf("%s is RAM-backed; no on-disk path to reject", dir)
		}
		if err := requireKeyOutRAMBacked(filepath.Join(dir, "key.pem")); err == nil {
			t.Fatal("expected a key-out on persistent storage to be refused")
		}
	})
}

func TestLoadOrGenerateKey(t *testing.T) {
	t.Run("generate ephemeral", func(t *testing.T) {
		key, keyPEM, err := loadOrGenerateKey(config{})
		if err != nil {
			t.Fatalf("loadOrGenerateKey: %v", err)
		}
		if key == nil {
			t.Fatal("nil key")
		}
		if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
			t.Fatalf("keyPEM does not look like a PEM key: %q", keyPEM)
		}
		if key.Curve != elliptic.P256() {
			t.Fatalf("curve = %v, want P-256", key.Curve.Params().Name)
		}
	})

	t.Run("load from disk", func(t *testing.T) {
		dir := t.TempDir()
		genKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		genPEM, err := certutil.MarshalECKeyPEM(genKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(path, genPEM, 0600); err != nil {
			t.Fatal(err)
		}

		key, keyPEM, err := loadOrGenerateKey(config{KeyPath: path})
		if err != nil {
			t.Fatalf("loadOrGenerateKey: %v", err)
		}
		if !key.Equal(genKey) {
			t.Fatal("loaded key does not match written key")
		}
		if string(keyPEM) != string(genPEM) {
			t.Fatal("returned PEM does not match file contents")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, _, err := loadOrGenerateKey(config{KeyPath: filepath.Join(t.TempDir(), "nope.pem")}); err == nil {
			t.Fatal("loadOrGenerateKey succeeded, want error for missing file")
		}
	})

	t.Run("invalid key contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(path, []byte("not a key"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadOrGenerateKey(config{KeyPath: path}); err == nil {
			t.Fatal("loadOrGenerateKey succeeded, want error for invalid key")
		}
	})
}

func TestCreateCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	armtlsExt := pkix.Extension{Id: armtls.OIDARMTLSAttestation, Value: []byte{0x30, 0x03, 0x02, 0x01, 0x42}}

	parseCSR := func(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
		t.Helper()
		block, _ := pem.Decode(csrPEM)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			t.Fatalf("not a CSR PEM: %q", csrPEM)
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse CSR: %v", err)
		}
		return csr
	}

	t.Run("dns san", func(t *testing.T) {
		csrPEM, err := createCSR(key, "host.example.com", armtlsExt)
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		csr := parseCSR(t, csrPEM)
		// INVARIANT: the CSR carries the armTLS extension so CDS can copy it
		// into the issued leaf for downstream armtls-mode re-verification.
		found := false
		for _, ext := range csr.Extensions {
			if ext.Id.Equal(armtls.OIDARMTLSAttestation) {
				found = true
				if string(ext.Value) != string(armtlsExt.Value) {
					t.Fatalf("armTLS ext value = %x, want %x", ext.Value, armtlsExt.Value)
				}
			}
		}
		if !found {
			t.Fatal("CSR missing the armTLS attestation extension")
		}
	})

	t.Run("ip san", func(t *testing.T) {
		csrPEM, err := createCSR(key, "10.0.0.5", armtlsExt)
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		if !strings.Contains(string(csrPEM), "CERTIFICATE REQUEST") {
			t.Fatalf("not a CSR PEM: %q", csrPEM)
		}
	})

	// The workload-claims flow embeds an armTLS attestation extension into the
	// CSR so CDS copies it onto the leaf (docs/armtls.md). Confirm an extra
	// extension survives into the request.
	t.Run("carries extra extension", func(t *testing.T) {
		want := []byte{0x30, 0x03, 0x02, 0x01, 0x2A}
		csrPEM, err := createCSR(key, "host.example.com", pkix.Extension{Id: armtls.OIDARMTLSAttestation, Value: want})
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse csr: %v", err)
		}
		found := false
		for _, ext := range csr.Extensions {
			if ext.Id.Equal(armtls.OIDARMTLSAttestation) {
				found = true
				if !bytes.Equal(ext.Value, want) {
					t.Fatalf("extension value = %x, want %x", ext.Value, want)
				}
			}
		}
		if !found {
			t.Fatal("armTLS extension not carried into the CSR")
		}
	})
}

// The extension embedded in the CSR must bind the bare public key: REPORTDATA
// = SHA-384(pubkey) with NO nonce, or downstream verifiers calling
// armtls.VerifyCert(cert, policy, nil) can never re-verify the issued leaf
// (the report_data mismatch bug this flow fixes).
func TestAttestationExtensionBindsBareKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var sawReportData []byte
	attestationApi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Errorf("attestation-api path = %s, want /attest", r.URL.Path)
		}
		var req remote.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode attest request: %v", err)
		}
		sawReportData = append([]byte(nil), req.ReportData...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"platform":"az-snp","evidence":{"quote":"abc"}}`)
	}))
	defer attestationApi.Close()

	ext, err := attestclient.NewClient("").AttestationExtension(context.Background(), attestationApi.URL, &key.PublicKey)
	if err != nil {
		t.Fatalf("AttestationExtension: %v", err)
	}

	want, err := armtls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(sawReportData) != string(want[:sha512.Size384]) {
		t.Fatalf("report_data sent to attestation-api = %x, want SHA-384(pubkey) = %x", sawReportData, want[:sha512.Size384])
	}

	att, err := armtls.UnmarshalExtension(ext.Value)
	if err != nil {
		t.Fatalf("unmarshal extension: %v", err)
	}
	if att.Family != armtls.TEETypeSEVSNP {
		t.Fatalf("TEEType = %v, want SEV-SNP", att.Family)
	}
}

func TestSnapshotReloadWatchPathsErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		if _, err := snapshotReloadWatchPaths([]string{filepath.Join(dir, "nope")}); err == nil {
			t.Fatal("snapshotReloadWatchPaths succeeded, want error for missing file")
		}
	})

	t.Run("directory not allowed", func(t *testing.T) {
		if _, err := snapshotReloadWatchPaths([]string{dir}); err == nil {
			t.Fatal("snapshotReloadWatchPaths succeeded, want error for directory")
		}
	})
}

func TestReloadWatchChangedPropagatesError(t *testing.T) {
	if _, _, err := reloadWatchChanged(nil, []string{filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("reloadWatchChanged succeeded, want error for missing file")
	}
}

func TestWriteOutputsAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	certPEM := testIssuedChainPEM(t)
	cfg := config{
		SAN:                    "host.example.com",
		OutPath:                filepath.Join(dir, "cert.pem"),
		CAOutPath:              filepath.Join(dir, "ca.pem"),
		KeyOutPath:             filepath.Join(dir, "key.pem"),
		DiscoveryOutPath:       filepath.Join(dir, "discovery.json"),
		DiscoveryPublicTLSMode: "cds",
	}
	result := attestclient.CertificateResult{
		Certificate: certPEM,
		Challenge:   base64.StdEncoding.EncodeToString([]byte("challenge")),
		Platform:    "snp",
		Evidence:    json.RawMessage(`{"q":"e"}`),
	}

	if err := writeOutputs(cfg, []byte("KEYPEM"), result); err != nil {
		t.Fatalf("writeOutputs: %v", err)
	}

	cert, err := os.ReadFile(cfg.OutPath)
	if err != nil || string(cert) != certPEM {
		t.Fatalf("cert out mismatch: err=%v", err)
	}
	if data, err := os.ReadFile(cfg.KeyOutPath); err != nil || string(data) != "KEYPEM" {
		t.Fatalf("key out mismatch: err=%v", err)
	}
	info, err := os.Stat(cfg.KeyOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode = %#o, want 0600", info.Mode().Perm())
	}
	ca, err := os.ReadFile(cfg.CAOutPath)
	if err != nil || !strings.Contains(string(ca), "CERTIFICATE") {
		t.Fatalf("ca out mismatch: err=%v", err)
	}
	var doc types.DiscoveryDocument
	data, err := os.ReadFile(cfg.DiscoveryOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("discovery json: %v", err)
	}
	if doc.PublicTLS.Hostname != "host.example.com" {
		t.Fatalf("discovery hostname = %q", doc.PublicTLS.Hostname)
	}
}

func TestWriteOutputsKeyPermissions(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, existing := range []os.FileMode{0, 0600, 0640, 0666} {
			t.Run(fmt.Sprintf("shared=%t/existing=%04o", shared, existing), func(t *testing.T) {
				dir := t.TempDir()
				dirMode := os.FileMode(0700)
				want := os.FileMode(0600)
				if shared {
					dirMode = 0770 | os.ModeSetgid
					want = 0640
				}
				if err := os.Chmod(dir, dirMode); err != nil {
					t.Fatal(err)
				}
				keyPath := filepath.Join(dir, "key.pem")
				if existing != 0 {
					if err := os.WriteFile(keyPath, []byte("old key"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(keyPath, existing); err != nil {
						t.Fatal(err)
					}
				}
				cfg := config{KeyOutPath: keyPath, OutPath: filepath.Join(dir, "cert.pem")}
				// Check both initial issuance and renewal.
				for _, content := range []string{"new key", "renewed key"} {
					if err := writeOutputs(cfg, []byte(content), attestclient.CertificateResult{}); err != nil {
						t.Fatal(err)
					}
					info, err := os.Stat(keyPath)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != want {
						t.Fatalf("key mode = %#o, want %#o", info.Mode().Perm(), want)
					}
					key, err := os.ReadFile(keyPath)
					if err != nil || string(key) != content {
						t.Fatalf("key = %q, err = %v; want %q", key, err, content)
					}
				}
			})
		}
	}
}

func TestWriteOutputsCAOutWithoutIssuerFails(t *testing.T) {
	// A chain with only a leaf has no CA bundle to extract.
	leafOnly := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("leaf")}))
	err := writeOutputs(config{CAOutPath: filepath.Join(t.TempDir(), "ca.pem")}, nil, attestclient.CertificateResult{Certificate: leafOnly})
	if err == nil {
		t.Fatal("writeOutputs succeeded, want error extracting CA bundle from leaf-only chain")
	}
}

func TestWriteOutputsPrintsToStdoutWithoutOutPath(t *testing.T) {
	// OutPath "" prints the chain to stdout; capture it via a pipe.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	writeErr := writeOutputs(config{}, nil, attestclient.CertificateResult{Certificate: "CHAIN-PEM"})
	os.Stdout = oldStdout
	w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr != nil {
		t.Fatalf("writeOutputs: %v", writeErr)
	}
	if string(out) != "CHAIN-PEM" {
		t.Fatalf("stdout = %q, want CHAIN-PEM", out)
	}
}

func TestBuildDiscoveryDocumentRejectsUnparseableCert(t *testing.T) {
	if _, err := buildDiscoveryDocument(config{}, attestclient.CertificateResult{Certificate: "junk"}); err == nil {
		t.Fatal("buildDiscoveryDocument succeeded, want parse error")
	}
}

func TestNewCDSClientInvalidURL(t *testing.T) {
	if _, err := newCDSClient(config{CDSURL: "://bad"}); err == nil {
		t.Fatal("newCDSClient succeeded, want error for invalid URL")
	}
}

func TestSetupLoggingSetsLevel(t *testing.T) {
	old := slog.Default()
	defer slog.SetDefault(old)

	setupLogging(true)
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("verbose logging did not enable debug level")
	}

	setupLogging(false)
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("non-verbose logging left debug level enabled")
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("non-verbose logging disabled info level")
	}
}

// startFakeServers wires up an httptest server playing the CDS role
// (/authenticate, /attest) and a separate attestation-api server (/attest).
// The challenge is valid base64 and the attestation-api echoes evidence so the
// full obtainCert flow can run without real TEE hardware.
func startFakeServers(t *testing.T, issuedChain string) (cdsURL, attURL string) {
	return startFakeServersRefusing(t, issuedChain, 0)
}

// startFakeServersRefusing is startFakeServers with the CDS refusing the first
// refusals authentication attempts before it starts issuing, so a test can
// watch get-cert recover from a CDS that is not yet ready to issue.
func startFakeServersRefusing(t *testing.T, issuedChain string, refusals int) (cdsURL, attURL string) {
	t.Helper()

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			http.NotFound(w, r)
			return
		}
		// snp evidence must carry a full-size attestation_report; the CSR
		// extension build extracts the raw report bytes for the on-cert form.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": mockapi.FakeSNPEvidence(nil),
		})
	}))
	t.Cleanup(att.Close)

	var mu sync.Mutex
	var asked int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			mu.Lock()
			asked++
			refuse := asked <= refusals
			mu.Unlock()
			if refuse {
				http.Error(w, `{"error":"csr_denied"}`, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge": base64.StdEncoding.EncodeToString([]byte("the-challenge")),
			})
		case "/attest":
			_, _ = w.Write([]byte(issuedChain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)

	return cds.URL, att.URL
}

func TestObtainCertEndToEnd(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServers(t, chain)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
	}
	client := plaintextCDSClient(cfg.CDSURL)
	if _, err := obtainCert(context.Background(), cfg, client); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}
	got, err := os.ReadFile(cfg.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != chain {
		t.Fatalf("written cert does not match issued chain")
	}
}

func TestObtainCertCDSError(t *testing.T) {
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": mockapi.FakeSNPEvidence(nil)})
	}))
	t.Cleanup(att.Close)
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(cds.Close)

	cfg := config{CDSURL: cds.URL, AttestationApiURL: att.URL, SAN: "host.example.com"}
	client := plaintextCDSClient(cfg.CDSURL)
	if _, err := obtainCert(context.Background(), cfg, client); err == nil {
		t.Fatal("obtainCert succeeded, want error when CDS fails")
	}
}

func TestObtainCertAttestationExtensionError(t *testing.T) {
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "attestation down", http.StatusInternalServerError)
	}))
	t.Cleanup(att.Close)
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authenticate" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challenge": base64.StdEncoding.EncodeToString([]byte("the-challenge")),
		})
	}))
	t.Cleanup(cds.Close)

	cfg := config{
		CDSURL:            cds.URL,
		AttestationApiURL: att.URL,
		SAN:               "host.example.com",
	}
	_, err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL))
	if err == nil {
		t.Fatal("obtainCert succeeded, want attestation extension error")
	}
	if !strings.Contains(err.Error(), "build armTLS attestation extension") {
		t.Fatalf("error = %v, want attestation extension error", err)
	}
}

func TestObtainCertWithRetrySucceedsAfterTransientFailure(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": mockapi.FakeSNPEvidence(nil)})
	}))
	t.Cleanup(att.Close)

	var calls int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			calls++
			if calls == 1 {
				http.Error(w, "warming up", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge": base64.StdEncoding.EncodeToString([]byte("c")),
			})
		case "/attest":
			_, _ = w.Write([]byte(chain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)

	cfg := config{
		CDSURL:               cds.URL,
		AttestationApiURL:    att.URL,
		SAN:                  "host.example.com",
		OutPath:              filepath.Join(dir, "cert.pem"),
		InitialRetryTimeout:  5 * time.Second,
		InitialRetryInterval: time.Millisecond,
	}
	client := plaintextCDSClient(cfg.CDSURL)
	if _, err := obtainCertWithRetry(context.Background(), cfg, client); err != nil {
		t.Fatalf("obtainCertWithRetry: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected a retry, got %d calls", calls)
	}
}

func TestObtainCertWithRetryNoTimeoutTriesOnce(t *testing.T) {
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": mockapi.FakeSNPEvidence(nil)})
	}))
	t.Cleanup(att.Close)
	var calls int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(cds.Close)

	cfg := config{CDSURL: cds.URL, AttestationApiURL: att.URL, SAN: "host.example.com", InitialRetryTimeout: 0}
	client := plaintextCDSClient(cfg.CDSURL)
	if _, err := obtainCertWithRetry(context.Background(), cfg, client); err == nil {
		t.Fatal("obtainCertWithRetry succeeded, want error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want exactly 1 with no retry timeout", calls)
	}
}

func TestRunValidationError(t *testing.T) {
	if err := run(config{CDSURL: "", AttestationApiURL: "http://a", SAN: "h"}); err == nil {
		t.Fatal("run succeeded, want validation error")
	}
}

// The socket directory is a mount injected at container creation: absent means
// it cannot appear within this container's lifetime, so run must fail (and the
// process exit, prompting a restart that replays the mount injection) rather
// than idle behind --continue-on-initial-error.
func TestRunFailsFastWithoutClaimsSocketDir(t *testing.T) {
	if _, err := os.Stat(workloadclaims.SidecarSocketDir); err == nil {
		t.Skipf("%s exists on this host", workloadclaims.SidecarSocketDir)
	}
	err := run(config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
		WorkloadClaims:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "inventory socket directory") {
		t.Fatalf("run() = %v, want the missing socket-directory failure", err)
	}
}

func TestRunFailsOnUnwritableOutputPath(t *testing.T) {
	err := run(config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
		OutPath:           filepath.Join(t.TempDir(), "missing", "cert.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error = %v, want missing output directory error", err)
	}
}

func TestRunFailsOnBadCDSMeasurements(t *testing.T) {
	err := run(config{
		CDSURL:            "https://cds:8443",
		CDSMeasurements:   "zz",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	})
	if err == nil || !strings.Contains(err.Error(), "--cds-measurements") {
		t.Fatalf("error = %v, want measurements error", err)
	}
}

func TestRunOnceReturnsInitialError(t *testing.T) {
	// Run-once mode (RenewInterval 0): the initial failure is returned as-is.
	err := run(config{
		CDSURL:              "https://127.0.0.1:1",
		AttestationApiURL:   "http://127.0.0.1:1",
		SAN:                 "host.example.com",
		InitialRetryTimeout: 0,
	})
	if err == nil {
		t.Fatal("run succeeded, want initial certificate request error")
	}
}

// serveSandboxRoute runs an inventory-shaped HTTP server on a unix socket and
// points the package's inventoryEndpoint at it for the test's lifetime.
func serveSandboxRoute(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "inv.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(workloadclaims.SandboxPath, handler)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	old := inventoryEndpoint
	inventoryEndpoint = func() string { return "unix://" + sock }
	t.Cleanup(func() { inventoryEndpoint = old })
}

func TestFetchSandboxToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("challenge-nonce")
	baseCfg := config{WorkloadClaims: true, WorkloadClaimsTimeout: 5 * time.Second}

	t.Run("disabled returns no token and no fetch", func(t *testing.T) {
		serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
			t.Error("the inventory must not be consulted without --workload-claims")
		})
		raw, err := fetchSandboxToken(context.Background(), config{}, &key.PublicKey, nonce)
		if err != nil || raw != nil {
			t.Fatalf("= %v, %v; want nil, nil", raw, err)
		}
	})

	t.Run("route absent issues without a sandbox ID", func(t *testing.T) {
		serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		raw, err := fetchSandboxToken(context.Background(), baseCfg, &key.PublicKey, nonce)
		if err != nil {
			t.Fatalf("a 404 route must degrade to tokenless issuance, got %v", err)
		}
		if raw != nil {
			t.Fatalf("token = %s, want none", raw)
		}
	})

	t.Run("any other inventory failure is fail-closed", func(t *testing.T) {
		serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		if _, err := fetchSandboxToken(context.Background(), baseCfg, &key.PublicKey, nonce); err == nil {
			t.Fatal("a 500 from the inventory must abort issuance, not drop the binding")
		}
	})

	t.Run("served token is forwarded as raw JSON", func(t *testing.T) {
		serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(workloadclaims.SignedSandboxToken{
				Token:     []byte("token-der"),
				Signature: []byte("signature"),
			})
		})
		raw, err := fetchSandboxToken(context.Background(), baseCfg, &key.PublicKey, nonce)
		if err != nil {
			t.Fatalf("fetchSandboxToken: %v", err)
		}
		var got workloadclaims.SignedSandboxToken
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("returned token is not the JSON CDS expects: %v", err)
		}
		if string(got.Token) != "token-der" || string(got.Signature) != "signature" {
			t.Fatalf("token roundtrip = %+v", got)
		}
	})
}

// testIssuedChainPEM builds a two-cert PEM chain (leaf + one issuer) that parses
// as real certificates, so buildDiscoveryDocument and caBundleFromChain succeed.
func testIssuedChainPEM(t *testing.T) string {
	t.Helper()
	leaf := testCertificatePEM(t)
	ca := testCertificatePEM(t)
	return leaf + ca
}
