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
			// A pod the injector selected no SAN for requests none.
			name: "no san",
			cfg: config{
				CDSURL:            "http://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
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
				CAPath:            "/tls/ca.pem",
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
		{"url san", func(c *config) { c.SAN = "https://host.example.com" }},
		{"negative ca watch interval", func(c *config) {
			c.CAPath = "/tls/ca.pem"
			c.RenewInterval = time.Hour
			c.CAWatchInterval = -time.Minute
		}},
		{"ca watch without renew interval", func(c *config) {
			c.CAPath = "/tls/ca.pem"
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

	// A pod without confidential.ai/cw requests no SAN at all; CDS takes
	// the subject from the verified workload identity assertion.
	t.Run("no san", func(t *testing.T) {
		csrPEM, err := createCSR(key, "", armtlsExt)
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		csr := parseCSR(t, csrPEM)
		if len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 {
			t.Fatalf("CSR carries SANs %v %v, want none", csr.DNSNames, csr.IPAddresses)
		}
		if len(csr.Subject.String()) != 0 {
			t.Fatalf("CSR subject = %q, want empty", csr.Subject.String())
		}
	})

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

	// get-cert embeds an armTLS attestation extension into the CSR so CDS
	// copies it onto the leaf (docs/armtls.md). Confirm an extra extension
	// survives into the request.
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

func TestPublishedKeyPermissions(t *testing.T) {
	ca := newTestCA(t)
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared=%t", shared), func(t *testing.T) {
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
			v, err := credentialVolumeFor(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt"))
			if err != nil {
				t.Fatal(err)
			}
			key, keyPEM := testKey(t)
			// Both the initial publication and the renewal that follows it.
			for _, ttl := range []time.Duration{time.Hour, 2 * time.Hour} {
				if err := publishGeneration(v, testGeneration(t, ca, key, keyPEM, testInstanceID, ttl)); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(filepath.Join(v.dir, v.keyName))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != want {
					t.Fatalf("key mode = %#o, want %#o", info.Mode().Perm(), want)
				}
			}
		})
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
// startFakeServers is a CDS that issues the way the real one does: it reads the
// CSR and the sandbox token out of the attest request and signs a leaf for that
// key, naming the instance the token asserts.
func startFakeServers(t *testing.T, ca *testCA) (cdsURL, attURL string) {
	return startFakeServersRefusing(t, ca, 0)
}

// startFakeServersRefusing is startFakeServers with the CDS refusing the first
// refusals authentication attempts before it starts issuing, so a test can
// watch get-cert recover from a CDS that is not yet ready to issue.
func startFakeServersRefusing(t *testing.T, ca *testCA, refusals int) (cdsURL, attURL string) {
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
			chain, err := issueForAttestRequest(ca, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(chain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)

	return cds.URL, att.URL
}

// issueForAttestRequest mints the leaf an attest request asks for: CDS stamps
// the instance the inventory's token names, which is what the pod then checks.
func issueForAttestRequest(ca *testCA, r *http.Request) (string, error) {
	var req struct {
		CSR          string          `json:"csr"`
		SandboxToken json.RawMessage `json:"sandbox_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		return "", errors.New("attest request carries no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("CSR key is not ECDSA")
	}
	var instanceID string
	if len(req.SandboxToken) > 0 {
		var token workloadclaims.SignedSandboxToken
		if err := json.Unmarshal(req.SandboxToken, &token); err != nil {
			return "", err
		}
		if instanceID, err = workloadclaims.UnverifiedSandboxIDFromToken(token.Token); err != nil {
			return "", err
		}
	}
	return ca.issue(pub, instanceID, time.Hour)
}

// testCredentials is a pod that has published nothing yet: a fresh volume and
// the instance its inventory asserts.
func testCredentials(t *testing.T) *credentials {
	t.Helper()
	return &credentials{
		volume:     testVolume(t),
		instanceID: testInstanceID,
	}
}

// A validated response becomes the pod's first generation, and the CA key
// that signed it becomes the pod's binding.
func TestObtainCertPublishesAValidatedGeneration(t *testing.T) {
	ca := newTestCA(t)
	stageInventory(t, testInstanceID)
	cdsURL, attURL := startFakeServers(t, ca)

	cfg := config{
		CDSURL:                cdsURL,
		AttestationApiURL:     attURL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
	}
	creds := testCredentials(t)
	if err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), creds); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}
	assertReaderPaths(t, creds.volume, creds.current)
	if id, err := armtls.SandboxIDFromCert(creds.current.Leaf); err != nil || id != testInstanceID {
		t.Fatalf("published leaf names instance %q, %v", id, err)
	}
	want, err := issuerKeyIDOf(ca.cert)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := loadIssuerRecord(creds.volume); err != nil || record != want {
		t.Fatalf("issuer record = %q, %v; want the issuing CA key %q", record, err, want)
	}
}

// A chart component whose node runs no admission inventory
// (--no-workload-claims) asks for no assertion, never dials the inventory, and
// publishes a leaf that names no workload instance.
func TestObtainCertWithoutClaimsPublishesAnUnassertedLeaf(t *testing.T) {
	cdsURL, attURL := startFakeServers(t, newTestCA(t))

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		NoWorkloadClaims:  true,
	}
	creds := testCredentials(t)
	creds.instanceID = ""
	if err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), creds); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}
	assertReaderPaths(t, creds.volume, creds.current)
	if id, err := armtls.SandboxIDFromCert(creds.current.Leaf); err != nil || id != "" {
		t.Fatalf("published leaf names instance %q, %v", id, err)
	}
}

// The mount requirement and the assertion are one decision: --no-workload-claims
// drops both, and nothing else does.
func TestWorkloadInstanceWithoutClaimsNeedsNoInventory(t *testing.T) {
	previous := nodeInventory.requireMount
	nodeInventory.requireMount = func() error { return errors.New("inventory socket directory is not mounted") }
	t.Cleanup(func() { nodeInventory.requireMount = previous })

	id, err := workloadInstance(context.Background(), config{NoWorkloadClaims: true})
	if err != nil || id != "" {
		t.Fatalf("workloadInstance = %q, %v, want no instance and no error", id, err)
	}
	if _, err := workloadInstance(context.Background(), config{}); err == nil {
		t.Fatal("a pod that asks for claims was resumed without the inventory mount")
	}
}

// A rejected assertion and an inaccessible inventory publish nothing, and
// neither degrades to an unstamped certificate.
func TestObtainCertFailsClosedWithoutAnAssertion(t *testing.T) {
	ca := newTestCA(t)
	for name, handler := range map[string]http.HandlerFunc{
		"rejected":    func(w http.ResponseWriter, r *http.Request) { http.Error(w, "denied", http.StatusForbidden) },
		"unsupported": func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
	} {
		t.Run(name, func(t *testing.T) {
			serveSandboxRoute(t, handler)
			cdsURL, attURL := startFakeServers(t, ca)
			cfg := config{
				CDSURL:                cdsURL,
				AttestationApiURL:     attURL,
				SAN:                   "host.example.com",
				WorkloadClaimsTimeout: 5 * time.Second,
			}
			creds := testCredentials(t)
			if err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), creds); err == nil {
				t.Fatal("issued without a workload identity assertion")
			}
			if creds.current != nil {
				t.Fatal("a generation was published without an assertion")
			}
		})
	}
}

// The inventory asserts one instance and CDS names another; the pod publishes
// nothing.
func TestObtainCertRejectsAnotherInstancesLeaf(t *testing.T) {
	stageInventory(t, "f3a8c1d2e4b69075")
	cdsURL, attURL := startFakeServers(t, newTestCA(t))

	cfg := config{
		CDSURL:                cdsURL,
		AttestationApiURL:     attURL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
	}
	creds := testCredentials(t)
	if err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), creds); err == nil {
		t.Fatal("published a leaf naming another workload instance")
	}
	if _, err := storedGeneration(creds.volume); !errors.Is(err, errNoGeneration) {
		t.Fatal("a generation for another instance was published")
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

	stageInventory(t, testInstanceID)
	cfg := config{
		CDSURL:                cds.URL,
		AttestationApiURL:     att.URL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
	}
	if err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), testCredentials(t)); err == nil {
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

	stageInventory(t, testInstanceID)
	cfg := config{
		CDSURL:                cds.URL,
		AttestationApiURL:     att.URL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
	}
	err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), testCredentials(t))
	if err == nil {
		t.Fatal("obtainCert succeeded, want attestation extension error")
	}
	if !strings.Contains(err.Error(), "build armTLS attestation extension") {
		t.Fatalf("error = %v, want attestation extension error", err)
	}
}

func TestObtainCertWithRetrySucceedsAfterTransientFailure(t *testing.T) {
	stageInventory(t, testInstanceID)
	cdsURL, attURL := startFakeServersRefusing(t, newTestCA(t), 1)

	cfg := config{
		CDSURL:                cdsURL,
		AttestationApiURL:     attURL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
		InitialRetryTimeout:   5 * time.Second,
		InitialRetryInterval:  time.Millisecond,
	}
	creds := testCredentials(t)
	if err := obtainCertWithRetry(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), creds); err != nil {
		t.Fatalf("obtainCertWithRetry: %v", err)
	}
	if creds.current == nil {
		t.Fatal("the retried request published nothing")
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

	stageInventory(t, testInstanceID)
	cfg := config{
		CDSURL:                cds.URL,
		AttestationApiURL:     att.URL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
		InitialRetryTimeout:   0,
	}
	if err := obtainCertWithRetry(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL), testCredentials(t)); err == nil {
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
	dir := ramBackedDir(t)
	err := run(config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
		CertPath:          filepath.Join(dir, "tls.crt"),
		KeyPath:           filepath.Join(dir, "tls.key"),
		CAPath:            filepath.Join(dir, "ca.crt"),
	})
	if err == nil || !strings.Contains(err.Error(), "inventory socket directory") {
		t.Fatalf("run() = %v, want the missing socket-directory failure", err)
	}
}

func TestRunFailsOnBadCDSMeasurements(t *testing.T) {
	cfg := stagePodEnvironment(t, config{
		CDSURL:            "https://cds:8443",
		CDSMeasurements:   "zz",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	})
	if err := run(cfg); err == nil || !strings.Contains(err.Error(), "--cds-measurements") {
		t.Fatalf("error = %v, want measurements error", err)
	}
}

func TestRunFailsOnUnwritableOutputPath(t *testing.T) {
	cfg := stagePodEnvironment(t, config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	})
	missing := filepath.Join(t.TempDir(), "missing")
	cfg.CertPath = filepath.Join(missing, "tls.crt")
	cfg.KeyPath = filepath.Join(missing, "tls.key")
	cfg.CAPath = filepath.Join(missing, "ca.crt")
	if err := run(cfg); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error = %v, want missing output directory error", err)
	}
}

func TestRunRejectsASplitCredentialVolume(t *testing.T) {
	cfg := stagePodEnvironment(t, config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	})
	cfg.CAPath = filepath.Join(t.TempDir(), "ca.crt")
	if err := run(cfg); err == nil || !strings.Contains(err.Error(), "one directory") {
		t.Fatalf("error = %v, want the one-directory requirement", err)
	}
}

func TestRunOnceReturnsInitialError(t *testing.T) {
	// Run-once mode (RenewInterval 0): the initial failure is returned as-is.
	cfg := stagePodEnvironment(t, config{
		CDSURL:              "https://127.0.0.1:1",
		AttestationApiURL:   "http://127.0.0.1:1",
		SAN:                 "host.example.com",
		InitialRetryTimeout: 0,
	})
	if err := run(cfg); err == nil {
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

	old := nodeInventory.endpoint
	nodeInventory.endpoint = func() string { return "unix://" + sock }
	t.Cleanup(func() { nodeInventory.endpoint = old })
}

func TestFetchSandboxToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("challenge-nonce")
	cfg := config{WorkloadClaimsTimeout: 5 * time.Second}

	// An inventory without the route is a failure like any other. A
	// certificate issued without the assertion would name no instance, so the
	// pod could not check it against its own.
	t.Run("route absent is fail-closed", func(t *testing.T) {
		serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		if _, _, err := fetchSandboxToken(context.Background(), cfg, &key.PublicKey, nonce); err == nil {
			t.Fatal("a 404 route must abort issuance, not drop the binding")
		}
	})

	t.Run("any other inventory failure is fail-closed", func(t *testing.T) {
		serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		if _, _, err := fetchSandboxToken(context.Background(), cfg, &key.PublicKey, nonce); err == nil {
			t.Fatal("a 500 from the inventory must abort issuance, not drop the binding")
		}
	})

	t.Run("served token is forwarded with the instance it names", func(t *testing.T) {
		stageInventory(t, testInstanceID)
		raw, asserted, err := fetchSandboxToken(context.Background(), cfg, &key.PublicKey, nonce)
		if err != nil {
			t.Fatalf("fetchSandboxToken: %v", err)
		}
		if asserted != testInstanceID {
			t.Fatalf("asserted instance = %q, want %q", asserted, testInstanceID)
		}
		var got workloadclaims.SignedSandboxToken
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal forwarded token: %v", err)
		}
		if len(got.Token) == 0 || len(got.Signature) == 0 {
			t.Fatalf("forwarded token = %+v, want the inventory's", got)
		}
	})

	t.Run("a token that is not a token is fail-closed", func(t *testing.T) {
		serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(workloadclaims.SignedSandboxToken{
				Token:     []byte("nonsense"),
				Signature: []byte("sig"),
			})
		})
		if _, _, err := fetchSandboxToken(context.Background(), cfg, &key.PublicKey, nonce); err == nil {
			t.Fatal("accepted an unreadable token")
		}
	})
}

// The instance every generation must name comes from the inventory, and only
// from there.
func TestAssertedInstanceID(t *testing.T) {
	cfg := config{WorkloadClaimsTimeout: 5 * time.Second}

	stageInventory(t, testInstanceID)
	got, err := assertedInstanceID(context.Background(), cfg)
	if err != nil || got != testInstanceID {
		t.Fatalf("instance = %q, %v; want %q", got, err, testInstanceID)
	}

	for name, handler := range map[string]http.HandlerFunc{
		"an unreachable route": func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"a token that is not a token": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(workloadclaims.SignedSandboxToken{
				Token:     []byte("nonsense"),
				Signature: []byte("sig"),
			})
		},
		"an instance outside the extension charset": func(w http.ResponseWriter, r *http.Request) {
			signTokenFor(t, w, r, "not a sandbox id")
		},
	} {
		t.Run(name, func(t *testing.T) {
			serveSandboxRoute(t, handler)
			if _, err := assertedInstanceID(context.Background(), cfg); err == nil {
				t.Fatal("accepted an instance the inventory did not assert")
			}
		})
	}
}

// Every certificate is requested on a key of its own, and the key published
// with a certificate is the key that certificate was issued for.
func TestObtainCertRenewsOnAFreshKey(t *testing.T) {
	stageInventory(t, testInstanceID)
	cdsURL, attURL := startFakeServers(t, newTestCA(t))

	cfg := config{
		CDSURL:                cdsURL,
		AttestationApiURL:     attURL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
	}
	creds := testCredentials(t)
	client := plaintextCDSClient(cfg.CDSURL)

	first := publishOneGeneration(t, cfg, client, creds)
	second := publishOneGeneration(t, cfg, client, creds)
	if second.Key.Equal(first.Key) {
		t.Fatal("a renewal reused the key of the previous generation")
	}
	if second.Key.Curve != elliptic.P256() {
		t.Fatalf("renewal key curve = %v, want P-256", second.Key.Curve)
	}
}

// publishOneGeneration runs one certificate request and returns the generation
// it published, checking the leaf belongs to the key published with it.
func publishOneGeneration(t *testing.T, cfg config, client attestclient.Client, creds *credentials) *generation {
	t.Helper()
	if err := obtainCert(context.Background(), cfg, client, creds); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}
	published, err := storedGeneration(creds.volume)
	if err != nil {
		t.Fatal(err)
	}
	if !leafMatchesKey(published) {
		t.Fatal("the published leaf was not issued for the published key")
	}
	return published
}

// The discovery document names the published certificate; it is public metadata
// and not part of the generation.
func TestWriteDiscoveryDocument(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		SAN:                    "host.example.com",
		DiscoveryOutPath:       filepath.Join(dir, "discovery.json"),
		DiscoveryPublicTLSMode: "cds",
	}
	result := attestclient.CertificateResult{
		Certificate: testCertificatePEM(t),
		Challenge:   base64.StdEncoding.EncodeToString([]byte("challenge")),
		Platform:    "snp",
		Evidence:    json.RawMessage(`{"q":"e"}`),
	}
	if err := writeDiscoveryDocument(cfg, result); err != nil {
		t.Fatalf("writeDiscoveryDocument: %v", err)
	}
	var doc types.DiscoveryDocument
	data, err := os.ReadFile(cfg.DiscoveryOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("discovery json: %v", err)
	}
	if doc.PublicTLS.Hostname != "host.example.com" || doc.CDSTLS.CertificatePEM != result.Certificate {
		t.Fatalf("discovery document does not name the published certificate: %+v", doc)
	}
	if err := writeDiscoveryDocument(config{}, result); err != nil {
		t.Fatalf("without --discovery-out: %v", err)
	}
}

// A restart that cannot resume withdraws what the volume still points at. A
// crashlooping sidecar would otherwise leave an unvalidated generation readable
// for as long as the pod lives.
func TestRunWithdrawsWhenResumingFails(t *testing.T) {
	v, _, _ := publishedVolume(t, newTestCA(t))
	cfg := config{
		CDSURL:                "https://cds:8443",
		AttestationApiURL:     "http://attestation-api:8400",
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: time.Second,
		CertPath:              filepath.Join(v.dir, v.leafName),
		KeyPath:               filepath.Join(v.dir, v.keyName),
		CAPath:                filepath.Join(v.dir, v.caName),
	}
	// An inventory that refuses: the pod cannot know which instance it is, so
	// nothing it holds can be revalidated.
	serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	})

	if err := run(cfg); err == nil {
		t.Fatal("run succeeded without a workload identity assertion")
	}
	if _, err := os.Stat(cfg.CertPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the generation is still readable after a failed resume: %v", err)
	}
	if _, err := loadIssuerRecord(v); err != nil {
		t.Fatalf("the binding did not survive the failed resume: %v", err)
	}
}
