package podstatus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
)

const pods = `{"kind":"PodList","apiVersion":"v1","items":[
 {"metadata":{"name":"other","uid":"u0"}},
 {"metadata":{"name":"app","uid":"u1"},"status":{"phase":"Running","podIP":"10.255.254.2"}}]}`

func serve(h Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHandlerReturnsOnlyTheSignedPod(t *testing.T) {
	h := Handler{UID: "u1", Pods: func(context.Context) ([]byte, error) { return []byte(pods), nil }}
	rec := serve(h, http.MethodGet, PodPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var pod corev1.Pod
	if err := json.Unmarshal(rec.Body.Bytes(), &pod); err != nil {
		t.Fatal(err)
	}
	if pod.Name != "app" || pod.Status.Phase != corev1.PodRunning {
		t.Fatalf("pod %+v", pod)
	}

	h.UID = "missing"
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown uid: %d", rec.Code)
	}
	h.Pods = func(context.Context) ([]byte, error) { return nil, errors.New("down") }
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("kubelet down: %d", rec.Code)
	}
	if rec := serve(h, http.MethodPost, PodPath); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	if rec := serve(h, http.MethodGet, "/pods"); rec.Code != http.StatusNotFound {
		t.Fatalf("other path: %d", rec.Code)
	}
}

func TestGetValidatesInputsBeforeDialing(t *testing.T) {
	ok := AttestConfig{Node: "10.0.0.5", LaunchKeyPubPath: "pub", ImageManifestPath: "m.json", Timeout: time.Second}
	tests := []struct {
		name   string
		change func(*AttestConfig)
		want   string
	}{
		{"no node", func(c *AttestConfig) { c.Node = "" }, "required"},
		{"no key", func(c *AttestConfig) { c.LaunchKeyPubPath = "" }, "required"},
		{"no manifest", func(c *AttestConfig) { c.ImageManifestPath = "" }, "required"},
		{"zero timeout", func(c *AttestConfig) { c.Timeout = 0 }, "--timeout"},
		{"url node", func(c *AttestConfig) { c.Node = "https://10.0.0.5/x" }, "host or IP"},
		{"missing key file", func(c *AttestConfig) {}, "--launch-key-pub"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ok
			tc.change(&cfg)
			_, err := Get(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHostPort(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.5": "10.0.0.5:8443", "10.0.0.5:9443": "10.0.0.5:9443", "pod.local": "pod.local:8443"} {
		if got := hostPort(in); got != want {
			t.Fatalf("hostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServeRejectsMissingPlatform(t *testing.T) {
	if err := Serve(context.Background(), ServeConfig{}); err == nil || !strings.Contains(err.Error(), "--platform") {
		t.Fatalf("got %v", err)
	}
}

var (
	dA = "sha256:" + strings.Repeat("a", 64)
	dB = "sha256:" + strings.Repeat("b", 64)
)

// attestFixture serves a guest whose RTMR[3] holds the launch seed extended
// by registered, and whose journal lists journal.
func attestFixture(t *testing.T, registered, journal []string, relayKey crypto.PublicKey) AttestConfig {
	t.Helper()
	dir := t.TempDir()
	pub := []byte("pod launch key")
	pubPath := filepath.Join(dir, "pubkey")
	journalPath := filepath.Join(dir, "journal")
	if err := os.WriteFile(pubPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, []byte(strings.Join(journal, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var quoted []byte // report data the guest's quote carries
	var servingKey crypto.PublicKey
	h := Handler{
		UID: "u1", Journal: journalPath,
		Pods: func(context.Context) ([]byte, error) { return []byte(pods), nil },
		Evidence: func(_ context.Context, rd []byte) ([]byte, error) {
			quoted = append(make([]byte, 64)[:0], rd...)
			quoted = append(quoted, make([]byte, 64-len(rd))...)
			return []byte(`{}`), nil
		},
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(credrelease.WithServingKey(r.Context(), servingKey)))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	servingKey = srv.Certificate().PublicKey
	if relayKey != nil {
		servingKey = relayKey
	}
	oldClient, oldVerify := newClient, verifyFresh
	t.Cleanup(func() { newClient, verifyFresh = oldClient, oldVerify })
	newClient = func(string, []byte, time.Duration) (*http.Client, error) { return srv.Client(), nil }
	verifyFresh = func(_ string, key, _, reportData []byte, _ []string) (*teetypes.VerificationResult, error) {
		if string(key) != string(pub) || !slices.Equal(reportData, quoted) {
			return nil, errors.New("report data does not match the expected binding")
		}
		reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pub), registered)
		return &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX,
			Claims: teetypes.Claims{LaunchDigest: "11", PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])}}}, nil
	}
	return AttestConfig{Node: strings.TrimPrefix(srv.URL, "https://"), LaunchKeyPubPath: pubPath, ImageManifestPath: "m.json", Timeout: 5 * time.Second}
}

func TestAttestBindsMeasuredDigests(t *testing.T) {
	cfg := attestFixture(t, []string{dA, dB}, []string{dA, dB}, nil)
	report, _, err := Attest(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(report.MeasuredDigests, []string{dA, dB}) || len(report.RTMR3) != 96 || len(report.LaunchKeySHA256) != 64 {
		t.Fatalf("report %+v", report)
	}
	cfg.ExpectDigests = []string{dB, "busybox@" + dA}
	if _, _, err := Attest(context.Background(), cfg); err != nil {
		t.Fatalf("expected set in another order: %v", err)
	}
	cfg.ExpectDigests = []string{dA}
	if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("expected set mismatch: %v", err)
	}
	if body, err := Get(context.Background(), AttestConfig{Node: cfg.Node, LaunchKeyPubPath: cfg.LaunchKeyPubPath, ImageManifestPath: "m.json", Timeout: 5 * time.Second}); err != nil || !strings.Contains(string(body), `"app"`) {
		t.Fatalf("get: %s %v", body, err)
	}
}

func TestAttestRejectsDigestListsTheRegisterDoesNotExplain(t *testing.T) {
	dC := "sha256:" + strings.Repeat("c", 64)
	for name, journal := range map[string][]string{
		"tampered":  {dA, dC},
		"reordered": {dB, dA},
		"missing":   {dA},
		"extra":     {dA, dB, dC},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := attestFixture(t, []string{dA, dB}, journal, nil)
			if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "do not explain") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestMeasurementsAndEvidenceRoutes(t *testing.T) {
	h := Handler{Journal: filepath.Join(t.TempDir(), "absent"),
		Evidence: func(context.Context, []byte) ([]byte, error) { return []byte(`{"platform":"tdx"}`), nil }}
	if rec := serve(h, http.MethodGet, MeasurementsPath); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"digests":[]}` {
		t.Fatalf("no journal: %d %s", rec.Code, rec.Body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, EvidencePath, strings.NewReader(`{"nonce":"c2hvcnQ="}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short nonce: %d", rec.Code)
	}
	if rec := serve(h, http.MethodGet, EvidencePath); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET evidence: %d", rec.Code)
	}
}

// A quote taken on another connection (e.g. a host relaying to another pod
// CVM with the same launch key) binds a different certificate key.
func TestAttestRejectsEvidenceFromAnotherChannel(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := attestFixture(t, []string{dA}, []string{dA}, &other.PublicKey)
	if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "report data") {
		t.Fatalf("got %v", err)
	}
}

// ecdsaCert is a self-signed P-256 serving cert: armTLS keys are ECDSA.
func ecdsaCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// The guest's REPORT_DATA (48 bytes from the handler, zero-padded to 64 by
// attestation-api) must equal what the client hands the verifier, and the
// verifier pads the expected value to 64 bytes and compares exactly.
func TestEvidenceReportDataRoundTrip(t *testing.T) {
	cert := ecdsaCert(t)
	nonce := bytes.Repeat([]byte{7}, 32)
	var sent []byte
	h := Handler{Evidence: func(_ context.Context, rd []byte) ([]byte, error) { sent = rd; return []byte(`{}`), nil }}
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(credrelease.AttestRequest{Nonce: nonce})
	req := httptest.NewRequest(http.MethodPost, EvidencePath, bytes.NewReader(body))
	h.ServeHTTP(rec, req.WithContext(credrelease.WithServingKey(req.Context(), cert.Leaf.PublicKey)))
	if rec.Code != http.StatusOK || rec.Header().Get(BindingHeader) != BindingVersion {
		t.Fatalf("status %d header %q", rec.Code, rec.Header().Get(BindingHeader))
	}
	quoteReportData := append(slices.Clone(sent), make([]byte, 64-len(sent))...)
	want, err := EvidenceReportData(cert.Leaf.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 48 || !bytes.Equal(quoteReportData, want[:]) {
		t.Fatalf("guest REPORT_DATA %x, client expects %x", quoteReportData, want)
	}
	h2 := sha512.Sum384(append(must(x509.MarshalPKIXPublicKey(cert.Leaf.PublicKey)), nonce...))
	if !bytes.Equal(want[:48], h2[:]) || !bytes.Equal(want[48:], make([]byte, 16)) {
		t.Fatal("report data is not SHA-384(SPKI || nonce) zero-padded")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
