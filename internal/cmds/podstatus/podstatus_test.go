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
	"fmt"
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
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const pods = `{"kind":"PodList","apiVersion":"v1","items":[
 {"metadata":{"name":"other","uid":"u0"}},
 {"metadata":{"name":"app","uid":"u1"},"status":{"phase":"Running","podIP":"10.255.254.2"}}]}`

func serve(h Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// assigned is a handler's assignment holding uid, "" for none.
func assigned(uid string) *assignmentService { return &assignmentService{uid: uid} }

func TestHandlerReturnsOnlyTheSignedPod(t *testing.T) {
	h := Handler{assignment: assigned("u1"), Pods: func(context.Context) ([]byte, error) { return []byte(pods), nil }}
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

	h.assignment = assigned("missing")
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown uid: %d", rec.Code)
	}
	h.assignment = assigned("u1")
	h.Pods = func(context.Context) ([]byte, error) { return []byte(pods[:len(pods)/2]), nil }
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "unexpected") {
		t.Fatalf("truncated kubelet body: %d %s", rec.Code, rec.Body)
	}
	h.Pods = func(context.Context) ([]byte, error) { return nil, errors.New("down") }
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("kubelet down: %d", rec.Code)
	}
	// No kubelet runs before an assignment: the guest is unassigned, not
	// failing, and the kubelet is not asked.
	calls := 0
	h.assignment = assigned("")
	h.Pods = func(context.Context) ([]byte, error) { calls++; return []byte(pods), nil }
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusNotFound || calls != 0 {
		t.Fatalf("unassigned with no kubelet: %d after %d kubelet reads", rec.Code, calls)
	}
	if rec := serve(h, http.MethodPost, PodPath); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	if rec := serve(h, http.MethodGet, "/pods"); rec.Code != http.StatusNotFound {
		t.Fatalf("other path: %d", rec.Code)
	}
}

var (
	dA = "sha256:" + strings.Repeat("a", 64)
	dB = "sha256:" + strings.Repeat("b", 64)
)

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
	manifestPath := writeTDXManifest(t, dir)
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
		h.ServeHTTP(w, r.WithContext(armtls.WithServingKey(r.Context(), servingKey)))
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
	lastClaimed = nil
	// Like the armTLS client, this one leaves the certificate check to its own
	// VerifyConnection; the fixture has none, so the serving-key pin alone decides.
	newClient = func(exp guestverify.Policy, _ time.Duration) *http.Client {
		if !exp.MeasuresPolicies() {
			t.Error("channel policy does not replay the leaf's measured list")
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test fixture
	}
	verifyFresh = func(_, reportData []byte, exp guestverify.Policy) (*teetypes.VerificationResult, error) {
		lastClaimed = exp.MeasuredPolicies()
		if !slices.Equal(reportData, quoted) {
			return nil, errors.New("report data does not match the expected binding")
		}
		reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pub), registered)
		res := &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX,
			Claims: teetypes.Claims{LaunchDigest: "11", PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])}}}
		// The real gate accepts any prefix of the claimed list and marks a
		// list no prefix of which replays.
		if _, err := runtimemeasure.MatchBindingPrefix(res, pub, lastClaimed); err != nil {
			return nil, fmt.Errorf("%w: %w", err, guestverify.ErrPoliciesDoNotReplay)
		}
		return res, nil
	}
	return AttestConfig{Node: strings.TrimPrefix(srv.URL, "https://"), LaunchKeyPubPath: pubPath, ImageManifestPath: manifestPath, Timeout: 5 * time.Second}
}

// lastClaimed is the measured list the fixture's verifier was last asked to
// replay against the fresh evidence.
var lastClaimed []string

// writeTDXManifest writes a TDX image manifest with throwaway register pins.
func writeTDXManifest(t *testing.T, dir string) string {
	t.Helper()
	pin := func(b byte) string { return strings.Repeat(string(rune(b)), 96) }
	path := filepath.Join(dir, "manifest.json")
	manifest := `{"mrtd":"` + pin('1') + `","rtmr1":"` + pin('2') + `","rtmr2":"` + pin('3') + `"}`
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The fresh evidence is asked to replay exactly the list read on both
// sides of the quote, and every digest of it is judged against the
// expected set.
func TestAttestBindsMeasuredDigests(t *testing.T) {
	cfg := attestFixture(t, []string{dA, dB}, []string{dA, dB}, nil)
	report, _, err := Attest(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(report.MeasuredDigests, []string{dA, dB}) || len(report.RTMR3) != 96 || len(report.LaunchKeySHA256) != 64 {
		t.Fatalf("report %+v", report)
	}
	if !slices.Equal(lastClaimed, []string{dA, dB}) {
		t.Fatalf("claimed %v; want the list read from the guest", lastClaimed)
	}
	cfg.ExpectDigests = []string{dB, "busybox@" + dA}
	if _, _, err := Attest(context.Background(), cfg); err != nil {
		t.Fatalf("expected set in another order: %v", err)
	}
	cfg.ExpectDigests = []string{dA}
	if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("expected set mismatch: %v", err)
	}
	if body, err := Get(context.Background(), AttestConfig{Node: cfg.Node, LaunchKeyPubPath: cfg.LaunchKeyPubPath, ImageManifestPath: cfg.ImageManifestPath, Timeout: 5 * time.Second}); err != nil || !strings.Contains(string(body), `"app"`) {
		t.Fatalf("get: %s %v", body, err)
	}
}

// A list the register has not caught up with fails the full replay but is not
// final: the guest records before it extends. A register that took an extend
// the list does not record, in any position, replays no prefix of it and is
// final.
func TestAttestRejectsDigestListsTheRegisterDoesNotExplain(t *testing.T) {
	dC := "sha256:" + strings.Repeat("c", 64)
	for name, tc := range map[string]struct {
		journal []string
		final   bool
	}{
		"tampered":  {[]string{dA, dC}, true},
		"reordered": {[]string{dB, dA}, true},
		"missing":   {[]string{dA}, true},
		"extra":     {[]string{dA, dB, dC}, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := attestFixture(t, []string{dA, dB}, tc.journal, nil)
			_, _, err := Attest(context.Background(), cfg)
			if err == nil {
				t.Fatal("attested a list the register does not explain")
			}
			if got := errors.Is(err, ErrMeasuredHistoryDoesNotReplay); got != tc.final {
				t.Fatalf("final = %v, want %v: %v", got, tc.final, err)
			}
			if !tc.final && !strings.Contains(err.Error(), "do not explain") {
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

// A quote taken on another connection (e.g. a host relaying to another
// pod CVM with the same launch key) binds a different certificate key.
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
	body, _ := json.Marshal(types.NonceRequest{Nonce: nonce})
	req := httptest.NewRequest(http.MethodPost, EvidencePath, bytes.NewReader(body))
	h.ServeHTTP(rec, req.WithContext(armtls.WithServingKey(req.Context(), cert.Leaf.PublicKey)))
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

// A guest built from another revision names another report-data
// convention; the client refuses rather than failing on a REPORT_DATA
// mismatch it cannot explain.
func TestAttestRefusesUnknownBindingVersion(t *testing.T) {
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != EvidencePath {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set(BindingHeader, "armtls-key-nonce/v0")
			_, _ = w.Write([]byte(`{}`))
		})
	})
	if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `needs "armtls-key-nonce/v1"`) {
		t.Fatalf("got %v", err)
	}
}

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
