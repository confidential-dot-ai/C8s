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
	"encoding/pem"
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
// attestFixture serves a fake pod CVM: registered is what its quote's
// RTMR[3] replays, journal what it lists, relayKey a serving key other than
// the connection's (a relayed quote), and wrap optional middleware around
// the guest handler.
func attestFixture(t *testing.T, registered, journal []string, relayKey crypto.PublicKey, wrap ...func(http.Handler) http.Handler) AttestConfig {
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
	var guest http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(credrelease.WithServingKey(r.Context(), servingKey)))
	})
	for _, w := range wrap {
		guest = w(guest)
	}
	srv := httptest.NewUnstartedServer(guest)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	servingKey = srv.Certificate().PublicKey
	if relayKey != nil {
		servingKey = relayKey
	}
	oldClient, oldVerify := newClient, verifyFresh
	t.Cleanup(func() { newClient, verifyFresh = oldClient, oldVerify })
	// Like the armTLS client, this one leaves the certificate check to its own
	// VerifyConnection; the fixture has none, so the serving-key pin alone decides.
	newClient = func(string, []byte, time.Duration) (*http.Client, error) {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, nil //nolint:gosec // test fixture
	}
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

// After the first answer, every connection must present the attested
// serving key: a host that moves later reads to another pod CVM launched
// with the same launch key is caught, although that guest's certificate
// would pass the armTLS checks on its own.
func TestAttestPinsTheServingKey(t *testing.T) {
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil)
	_, client, err := Attest(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pods))
	}))
	other.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
	other.StartTLS()
	t.Cleanup(other.Close)
	if _, err := do(context.Background(), client, http.MethodGet, other.URL+PodPath, nil); err == nil || !strings.Contains(err.Error(), "serving key differs") {
		t.Fatalf("read from another guest: %v", err)
	}
	if _, err := do(context.Background(), client, http.MethodGet, "https://"+hostPort(cfg.Node)+PodPath, nil); err != nil {
		t.Fatalf("read from the attested guest: %v", err)
	}
}

// The kubelet's self-signed serving certificate is pinned by its bytes:
// the certificate kubelet wrote is accepted, any other is refused, and the
// pin follows the file.
func TestKubeletPodsPinsTheServingCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pods))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	certFile := filepath.Join(t.TempDir(), "kubelet.crt")
	writeCert := func(der []byte) {
		t.Helper()
		if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := kubeletPods(srv.URL, certFile)

	if _, err := read(context.Background()); err == nil || !strings.Contains(err.Error(), "read kubelet serving certificate") {
		t.Fatalf("no certificate file: %v", err)
	}
	writeCert(ecdsaCert(t).Certificate[0])
	if _, err := read(context.Background()); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("another certificate: %v", err)
	}
	writeCert(srv.Certificate().Raw)
	body, err := read(context.Background())
	if err != nil || !strings.Contains(string(body), `"app"`) {
		t.Fatalf("pinned certificate: %s %v", body, err)
	}
}

// The commands drive Attest and Get: pod-attest prints the report and fails
// on an expected set the pod did not measure; pod-status get prints the pod.
func TestCommandsRunAttestAndGet(t *testing.T) {
	cfg := attestFixture(t, []string{dA, dB}, []string{dA, dB}, nil)
	flags := []string{"--node", cfg.Node, "--launch-key-pub", cfg.LaunchKeyPubPath, "--image-manifest", cfg.ImageManifestPath}

	var out bytes.Buffer
	attest := NewAttestCmd()
	attest.SetOut(&out)
	attest.SetArgs(append(slices.Clone(flags), "--expect-digest", dB, "--expect-digest", dA))
	if err := attest.Execute(); err != nil {
		t.Fatalf("pod-attest: %v", err)
	}
	var report Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || !slices.Equal(report.MeasuredDigests, []string{dA, dB}) {
		t.Fatalf("pod-attest printed %s (%v)", out.String(), err)
	}

	attest = NewAttestCmd()
	attest.SetOut(&out)
	attest.SetErr(&out)
	attest.SetArgs(append(slices.Clone(flags), "--expect-digest", dA))
	if err := attest.Execute(); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("pod-attest with a short expected set: %v", err)
	}

	out.Reset()
	get := NewCmd()
	get.SetOut(&out)
	get.SetArgs(append([]string{"get"}, flags...))
	if err := get.Execute(); err != nil || !strings.Contains(out.String(), `"app"`) {
		t.Fatalf("pod-status get: %s %v", out.String(), err)
	}
}

// A guest built from another revision names another report-data
// convention; the client refuses rather than failing on a REPORT_DATA
// mismatch it cannot explain.
func TestAttestRefusesUnknownBindingVersion(t *testing.T) {
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&headerRewriter{ResponseWriter: w, name: BindingHeader, value: "armtls-key-nonce/v0"}, r)
		})
	})
	if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `needs "armtls-key-nonce/v1"`) {
		t.Fatalf("got %v", err)
	}
}

type headerRewriter struct {
	http.ResponseWriter
	name, value string
}

func (h *headerRewriter) WriteHeader(code int) {
	h.ResponseWriter.Header().Set(h.name, h.value)
	h.ResponseWriter.WriteHeader(code)
}

func (h *headerRewriter) Write(b []byte) (int, error) {
	h.ResponseWriter.Header().Set(h.name, h.value)
	return h.ResponseWriter.Write(b)
}

// The measured list must arrive as a 200 with a JSON body.
func TestAttestRejectsBrokenMeasurements(t *testing.T) {
	for name, respond := range map[string]func(http.ResponseWriter){
		"unavailable": func(w http.ResponseWriter) { http.Error(w, "measurements unavailable", http.StatusServiceUnavailable) },
		"not json":    func(w http.ResponseWriter) { _, _ = w.Write([]byte("digests")) },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := attestFixture(t, []string{dA}, []string{dA}, nil, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == MeasurementsPath {
						respond(w)
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "measurements") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// The pin needs a TLS transport to hang on and a key it can encode.
func TestPinServingKeyFailsClosed(t *testing.T) {
	key := ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).Public()
	if _, err := pinServingKey(&http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) { return nil, nil })}, key); err == nil || !strings.Contains(err.Error(), "no TLS transport") {
		t.Fatalf("non-TLS transport: %v", err)
	}
	if _, err := pinServingKey(&http.Client{Transport: &http.Transport{}}, "not a key"); err == nil || !strings.Contains(err.Error(), "pin serving key") {
		t.Fatalf("unencodable key: %v", err)
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Every attested request must arrive over TLS; a plain answer carries no
// serving key to bind evidence to.
func TestDoRequiresTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	t.Cleanup(srv.Close)
	if _, err := do(context.Background(), srv.Client(), http.MethodGet, srv.URL+PodPath, nil); err == nil || !strings.Contains(err.Error(), "did not arrive over TLS") {
		t.Fatalf("got %v", err)
	}
}

// Serve reads the staged launch configuration before anything else.
func TestServeRejectsBrokenStagedDocuments(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "config.json")
	if err := os.WriteFile(broken, []byte(`{"role":`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ path, want string }{
		"missing":   {filepath.Join(dir, "absent.json"), "absent.json"},
		"truncated": {broken, "decode staged launch configuration"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Serve(context.Background(), ServeConfig{Platform: "tdx", StagedPath: tc.path})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
