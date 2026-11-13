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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
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

// Once the plugin ended the pod identity, a kubelet under restartPolicy Always
// may keep the phase Running while it recreates refused containers; the
// service projects the pod as failed, so the provider stops it. A kubelet
// status that is already terminal stands. A plugin that cannot answer makes
// the status unavailable rather than letting the kubelet's cached view stand.
func TestHandlerProjectsAnEndedPodIdentityAsFailed(t *testing.T) {
	ended, pluginErr := true, error(nil)
	h := Handler{assignment: assigned("u1"), Pods: func(context.Context) ([]byte, error) { return []byte(pods), nil }, IdentityEnded: func(context.Context) (bool, error) { return ended, pluginErr }}
	read := func() PodProjection {
		rec := serve(h, http.MethodGet, PodPath)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		var got PodProjection
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if p := read(); p.Status.Phase != corev1.PodFailed {
		t.Fatalf("ended identity projected as %+v", p.Status)
	}
	if rec := serve(h, http.MethodGet, PodPath); strings.Contains(rec.Body.String(), "reason") {
		t.Fatalf("projection carries a guest reason: %s", rec.Body)
	}
	ended = false
	if p := read(); p.Status.Phase != corev1.PodRunning {
		t.Fatalf("live identity projected as %+v", p.Status)
	}
	pluginErr = errors.New("health socket unreachable")
	if rec := serve(h, http.MethodGet, PodPath); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreachable plugin: %d, want 503", rec.Code)
	}
	pluginErr = nil
	succeeded := strings.Replace(pods, `"phase":"Running"`, `"phase":"Succeeded"`, 1)
	h.Pods = func(context.Context) ([]byte, error) { return []byte(succeeded), nil }
	ended = true
	if p := read(); p.Status.Phase != corev1.PodSucceeded {
		t.Fatalf("terminal kubelet status rewritten: %+v", p.Status)
	}
	if _, err := podIdentityEndedAt(t.Context(), filepath.Join(t.TempDir(), "absent.sock")); err == nil {
		t.Fatal("an unreachable plugin answered")
	}
}

var (
	dA = "sha256:" + strings.Repeat("a", 64)
	dB = "sha256:" + strings.Repeat("b", 64)
)

// attestFixture serves a fake pod CVM: registered is what its quote's
// RTMR[3] replays, journal what it lists, relayKey a serving key other than
// the connection's (a relayed quote), and opts optional adjustments to the
// guest server before it starts.
func attestFixture(t *testing.T, registered, journal []string, relayKey crypto.PublicKey, opts ...func(*httptest.Server)) AttestConfig {
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
		assignment: assigned("u1"), Journal: journalPath,
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
	srv := httptest.NewUnstartedServer(guest)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
	for _, opt := range opts {
		opt(srv)
	}
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

// wrapGuest puts middleware around the fake guest's handler.
func wrapGuest(mw func(http.Handler) http.Handler) func(*httptest.Server) {
	return func(srv *httptest.Server) { srv.Config.Handler = mw(srv.Config.Handler) }
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
	_, client, err := Attest(context.Background(), AttestConfig{Node: cfg.Node, LaunchKeyPubPath: cfg.LaunchKeyPubPath, ImageManifestPath: cfg.ImageManifestPath, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	defer client.CloseIdleConnections()
	if body, _, _, err := doPeer(context.Background(), client, http.MethodGet, "https://"+hostPort(cfg.Node)+PodPath, nil); err != nil || !strings.Contains(string(body), `"app"`) {
		t.Fatalf("get: %s %v", body, err)
	}
}

// An empty expected set means no containers, unlike no expected set.
func TestAttestRefusesDigestsWhenNoneAreExpected(t *testing.T) {
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil)
	cfg.ExpectDigests = []string{}
	if _, _, err := Attest(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("a measured container passed an empty expected set: %v", err)
	}
}

// A list the register does not explain fails the full replay, whether the
// register took an extend the list does not record, in any position, or the
// list has run ahead of the register.
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
			if _, _, err := Attest(context.Background(), cfg); err == nil {
				t.Fatal("attested a list the register does not explain")
			}
		})
	}
}

// The service exits on every startup failure to confirm the launch key, a
// register that replays no prefix of the journal included.
func TestServeExitsWhenTheLaunchKeyIsNotConfirmed(t *testing.T) {
	staged := filepath.Join(t.TempDir(), "config.json")
	doc, err := json.Marshal(stagedPodDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	old := loadMeasuredLaunchKey
	t.Cleanup(func() { loadMeasuredLaunchKey = old })
	for name, failure := range map[string]error{
		"attestation-api not ready": errors.New("attestation-api not ready"),
		"no replaying prefix":       fmt.Errorf("%w: RTMR[3] carries another value", launchbinding.ErrRegisterDoesNotReplay),
	} {
		t.Run(name, func(t *testing.T) {
			loadMeasuredLaunchKey = func(context.Context, string, string) ([]byte, error) { return nil, failure }
			err := Serve(context.Background(), ServeConfig{Platform: "tdx", StagedPath: staged, ListenAddr: "127.0.0.1:0"})
			if err == nil || !strings.Contains(err.Error(), "load measured launch key") || !errors.Is(err, failure) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// `pod-status serve` runs Serve under the context it is executed with:
// cancelling it stops a Serve still waiting for its launch key.
func TestServeCommandStopsWithItsContext(t *testing.T) {
	staged := filepath.Join(t.TempDir(), "config.json")
	doc, err := json.Marshal(stagedPodDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	old := loadMeasuredLaunchKey
	t.Cleanup(func() { loadMeasuredLaunchKey = old })
	loading := make(chan struct{})
	loadMeasuredLaunchKey = func(ctx context.Context, _, _ string) ([]byte, error) {
		close(loading)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(t.Context())
	cmd := NewCmd()
	cmd.SetArgs([]string{"serve", "--platform=tdx", "--staged=" + staged})
	cmd.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	<-loading
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serve = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop after its context was cancelled")
	}
}

// stagedPodDocument is the generic pod document Serve reads before anything
// else.
func stagedPodDocument(t *testing.T) *podlaunch.Document {
	t.Helper()
	public := func() string {
		der, err := x509.MarshalPKIXPublicKey(&ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	return &podlaunch.Document{
		SchemaVersion: podlaunch.SchemaVersion, ClusterID: "cluster", Role: podlaunch.Pod,
		Node:                 podlaunch.Node{Name: "guest"},
		PodOperatorPublicKey: public(),
		CDS:                  cmdsutil.CDS{Address: "cds.example.org:8443", Measurements: testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)},
		Image:                podlaunch.Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}},
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
	if _, _, _, err := doPeer(context.Background(), client, http.MethodGet, other.URL+PodPath, nil); err == nil || !strings.Contains(err.Error(), "serving key differs") {
		t.Fatalf("read from another guest: %v", err)
	}
	if _, _, _, err := doPeer(context.Background(), client, http.MethodGet, "https://"+hostPort(cfg.Node)+PodPath, nil); err != nil {
		t.Fatalf("read from the attested guest: %v", err)
	}
}

// rotateServingKeyAfter presents another certificate from handshake n+1 on.
func rotateServingKeyAfter(t *testing.T, n int) func(*httptest.Server) {
	return func(srv *httptest.Server) {
		rotated := &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
		var handshakes atomic.Int64
		srv.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			if handshakes.Add(1) > int64(n) {
				return rotated, nil
			}
			return nil, nil
		}
		srv.Config.SetKeepAlivesEnabled(false)
	}
}

// The quote and the digest read after it travel over the pinned channel.
func TestAttestReadsEvidenceAndDigestsOverThePinnedChannel(t *testing.T) {
	for name, served := range map[string]int{"quote": 1, "second digest read": 2} {
		t.Run(name, func(t *testing.T) {
			cfg := attestFixture(t, []string{dA}, []string{dA}, nil, rotateServingKeyAfter(t, served))
			if _, _, err := Attest(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "serving key differs") {
				t.Fatalf("another guest answered the %s: %v", name, err)
			}
		})
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
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil, wrapGuest(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != EvidencePath {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set(BindingHeader, "armtls-key-nonce/v0")
			_, _ = w.Write([]byte(`{}`))
		})
	}))
	if _, _, err := Attest(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `needs "armtls-key-nonce/v1"`) {
		t.Fatalf("got %v", err)
	}
}

// Every attested request must arrive over TLS; a plain answer carries no
// serving key to bind evidence to.
func TestDoRequiresTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	t.Cleanup(srv.Close)
	if _, _, _, err := doPeer(context.Background(), srv.Client(), http.MethodGet, srv.URL+PodPath, nil); err == nil || !strings.Contains(err.Error(), "did not arrive over TLS") {
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

// Without an assignment service both assignment routes are unavailable.
func TestAssignmentRoutesWithoutAService(t *testing.T) {
	if rec := serve(Handler{}, http.MethodGet, AssignNoncePath); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nonce: %d", rec.Code)
	}
	if rec := serve(Handler{}, http.MethodPost, AssignPath); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("assign: %d", rec.Code)
	}
}

func TestEvidenceReportDataRequiresA32ByteNonce(t *testing.T) {
	key := &ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey
	if _, err := EvidenceReportData(key, make([]byte, 31)); err == nil || !strings.Contains(err.Error(), "got 31") {
		t.Fatalf("short nonce: %v", err)
	}
}

// Attest and Get refuse an incomplete configuration before any request.
func TestAttestRefusesInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	valid := AttestConfig{Node: "guest", LaunchKeyPubPath: filepath.Join(dir, "absent.pub"), ImageManifestPath: filepath.Join(dir, "manifest.json"), Timeout: time.Second}
	for _, tc := range []struct {
		name string
		edit func(*AttestConfig)
		want string
	}{
		{"no node", func(c *AttestConfig) { c.Node = "" }, "are required"},
		{"no timeout", func(c *AttestConfig) { c.Timeout = 0 }, "must be positive"},
		{"node with path", func(c *AttestConfig) { c.Node = "guest/evil" }, "must be a host or IP"},
		{"invalid digest", func(c *AttestConfig) { c.ExpectDigests = []string{"sha256:short"} }, "cfg.ExpectDigests"},
		{"missing launch key", func(c *AttestConfig) { c.ExpectDigests = []string{dA} }, "launch key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.edit(&cfg)
			if report, client, err := Attest(t.Context(), cfg); err == nil || report != nil || client != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("attest: %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHostPortDefaultsTheStatusPort(t *testing.T) {
	for node, want := range map[string]string{"guest": "guest:8443", "[::1]": "[::1]:8443", "guest:9000": "guest:9000"} {
		if got := hostPort(node); got != want {
			t.Fatalf("hostPort(%q) = %q, want %q", node, got, want)
		}
	}
}

// The pin needs a marshalable key and a TLS transport; it refuses a
// connection without a certificate and keeps the checks the client made.
func TestPinServingKeyKeepsTheClientChecks(t *testing.T) {
	key := &ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey
	if _, err := pinServingKey(&http.Client{Transport: &http.Transport{}}, struct{}{}); err == nil {
		t.Fatal("unsupported key pinned")
	}
	if _, err := pinServingKey(&http.Client{Transport: http.NewFileTransport(http.Dir(t.TempDir()))}, key); err == nil || !strings.Contains(err.Error(), "no TLS transport") {
		t.Fatalf("non-TLS transport: %v", err)
	}
	pinned, err := pinServingKey(&http.Client{Transport: &http.Transport{}}, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := pinned.Transport.(*http.Transport).TLSClientConfig
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("connection without a certificate: %v", err)
	}
	refused := errors.New("refused by the client")
	checked, err := pinServingKey(&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:       tls.VersionTLS12,
		VerifyConnection: func(tls.ConnectionState) error { return refused },
	}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: key}}}
	if err := checked.Transport.(*http.Transport).TLSClientConfig.VerifyConnection(cs); !errors.Is(err, refused) {
		t.Fatalf("client check dropped by the pin: %v", err)
	}
}

// tlsOnlyTransport serves over TLS but is not an *http.Transport, so the
// serving key cannot be pinned.
type tlsOnlyTransport struct{ http.RoundTripper }

func TestAttestReportsAnUnpinnableClient(t *testing.T) {
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil)
	newClient = func(guestverify.Policy, time.Duration) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test fixture
		return &http.Client{Transport: tlsOnlyTransport{transport}}
	}
	if _, _, err := Attest(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "no TLS transport") {
		t.Fatalf("unpinnable client: %v", err)
	}
}

// A kubelet without a certificate, or a pin file holding none, is refused.
func TestVerifyPinnedCertificateRequiresACertificate(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "kubelet.crt")
	if err := verifyPinnedCertificate(tls.ConnectionState{}, certFile); err == nil || !strings.Contains(err.Error(), "presented no certificate") {
		t.Fatalf("no peer certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(ecdsaCert(t).Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("key")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPinnedCertificate(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, certFile); err == nil || !strings.Contains(err.Error(), "holds no certificate") {
		t.Fatalf("pin file without a certificate: %v", err)
	}
}

// A kubelet that answers other than 200, or an unusable address, yields no pods.
func TestKubeletPodsRefusesFailedReads(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	certFile := filepath.Join(t.TempDir(), "kubelet.crt")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if body, err := kubeletPods(srv.URL, certFile)(t.Context()); err == nil || body != nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("unready kubelet: %s %v", body, err)
	}
	if _, err := kubeletPods("https://kubelet\x7f", certFile)(t.Context()); err == nil {
		t.Fatal("pods read from an invalid address")
	}
}

// A refused or malformed answer fails the read, keeping only the head of a
// long peer-controlled body; evidence without the binding header is refused.
func TestAttestedReadsRefuseFailedAnswers(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()

	status, body = http.StatusInternalServerError, strings.Repeat("e", 600)
	_, _, err := fetchDigests(t.Context(), client, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "measurements: 500") || !strings.HasSuffix(err.Error(), strings.Repeat("e", 512)+"...") {
		t.Fatalf("refused measurements: %v", err)
	}
	if _, _, err := postEvidence(t.Context(), client, srv.URL, []byte("{}")); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("refused evidence: %v", err)
	}
	status, body = http.StatusOK, "{"
	if digests, _, err := fetchDigests(t.Context(), client, srv.URL); err == nil || digests != nil {
		t.Fatalf("malformed measurements: %v %v", digests, err)
	}
	if _, _, err := postEvidence(t.Context(), client, srv.URL, []byte("{}")); err == nil || !strings.Contains(err.Error(), `binding is ""`) {
		t.Fatalf("evidence without binding: %v", err)
	}
	if _, _, _, err := doPeer(t.Context(), client, "BAD METHOD", srv.URL, nil); err == nil {
		t.Fatal("request with an invalid method sent")
	}
}

// Serve refuses a platform without armTLS, a launch key that is not one
// P-256 key, and an assignment directory it cannot own.
func TestServeRefusesUnusableConfiguration(t *testing.T) {
	if err := Serve(t.Context(), ServeConfig{Platform: " "}); err == nil || !strings.Contains(err.Error(), "--platform") {
		t.Fatalf("blank platform: %v", err)
	}
	staged := filepath.Join(t.TempDir(), "config.json")
	doc, err := json.Marshal(stagedPodDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	old := loadMeasuredLaunchKey
	t.Cleanup(func() { loadMeasuredLaunchKey = old })
	loadMeasuredLaunchKey = func(context.Context, string, string) ([]byte, error) { return []byte("not a key"), nil }
	if err := Serve(t.Context(), ServeConfig{Platform: "tdx", StagedPath: staged}); err == nil || !strings.Contains(err.Error(), "measured launch key: assignment requires") {
		t.Fatalf("unusable launch key: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("the assignment directory is writable by root")
	}
	der, err := x509.MarshalPKIXPublicKey(&ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	loadMeasuredLaunchKey = func(context.Context, string, string) ([]byte, error) {
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
	}
	if err := Serve(t.Context(), ServeConfig{Platform: "tdx", StagedPath: staged}); err == nil || !strings.Contains(err.Error(), "open assignment state") {
		t.Fatalf("assignment state outside a guest: %v", err)
	}
}

// Once the plugin ended the pod identity, the assignment routes answer 503
// before any assignment check. A live identity, or a plugin that cannot
// answer, leaves an assigned guest's 409; an unassigned guest is not asked.
func TestAssignmentRoutesAnswer503OnceThePodIdentityEnded(t *testing.T) {
	ended, pluginErr, asked := true, error(nil), 0
	identity := func(context.Context) (bool, error) { asked++; return ended, pluginErr }
	h := Handler{assignment: assigned("u1"), IdentityEnded: identity}
	codes := func() [2]int {
		return [2]int{serve(h, http.MethodGet, AssignNoncePath).Code, serve(h, http.MethodPost, AssignPath).Code}
	}
	if got := codes(); got != [2]int{http.StatusServiceUnavailable, http.StatusServiceUnavailable} {
		t.Fatalf("ended identity: %v", got)
	}
	ended = false
	if got := codes(); got != [2]int{http.StatusConflict, http.StatusConflict} {
		t.Fatalf("live identity: %v", got)
	}
	ended, pluginErr = true, errors.New("plugin unreachable")
	if got := codes(); got != [2]int{http.StatusConflict, http.StatusConflict} {
		t.Fatalf("unreachable plugin: %v", got)
	}
	asked = 0
	s, _, _, _ := assignmentFixture(t)
	if rec := serve(Handler{assignment: s, IdentityEnded: identity}, http.MethodGet, AssignNoncePath); rec.Code != http.StatusOK || asked != 0 {
		t.Fatalf("unassigned guest: %d, plugin asked %d times", rec.Code, asked)
	}
}

// A guest or kubelet answer past maxBody is refused where it is read: a
// truncated pod list or evidence response is never parsed.
func TestAnAnswerOverTheLimitIsRefused(t *testing.T) {
	guest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxBody+1))
	}))
	t.Cleanup(guest.Close)
	if _, _, err := postEvidence(t.Context(), guest.Client(), guest.URL, []byte("{}")); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("evidence: %v", err)
	}

	kubelet := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxBody+1))
	}))
	kubelet.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
	kubelet.StartTLS()
	t.Cleanup(kubelet.Close)
	certFile := filepath.Join(t.TempDir(), "kubelet.crt")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kubelet.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := kubeletPods(kubelet.URL, certFile)(t.Context()); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("kubelet /pods: %v", err)
	}
}
