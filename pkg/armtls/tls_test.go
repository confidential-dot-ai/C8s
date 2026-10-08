package armtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// fakeAttestFunc returns an AttestFunc that parses hex-encoded REPORTDATA
// from customData and wraps it in a fake SNP report. Suitable for tests
// that exercise TLS plumbing without real AMD hardware.
func fakeAttestFunc(_ context.Context, customData string) (string, error) {
	var rd [64]byte
	fmt.Sscanf(customData, "%x", &rd)
	return string(fakeSNPReport(rd)), nil
}

// testServerConfig returns a minimal ServerConfig for tests.
func testServerConfig() *ServerConfig {
	return &ServerConfig{
		Platform:   "sev-snp",
		DNSNames:   []string{"localhost"},
		CertTTL:    1 * time.Hour,
		AttestFunc: fakeAttestFunc,
	}
}

func TestNewServerTLSConfig(t *testing.T) {
	tlsCfg, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("GetCertificate is nil")
	}

	// Simulate a handshake to trigger cert provisioning.
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	if cert == nil {
		t.Fatal("cert is nil")
	}
	if cert.PrivateKey == nil {
		t.Error("private key is nil")
	}
	if len(cert.Certificate) == 0 {
		t.Error("no certificate chain")
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	requireARMTLSExtension(t, parsed)
}

func TestNewServerTLSConfigCaching(t *testing.T) {
	callCount := 0
	cfg := testServerConfig()
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount++
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First call provisions.
	_, err = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 attestation call, got %d", callCount)
	}

	// Second call should use cache.
	_, err = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 attestation call (cached), got %d", callCount)
	}
}

func TestNewServerTLSConfigWithClientPolicy(t *testing.T) {
	cfg := testServerConfig()
	cfg.ClientPolicy = &VerifyPolicy{}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate should be set when ClientPolicy is provided")
	}
}

func TestNewServerTLSConfigWithoutClientPolicy(t *testing.T) {
	tlsCfg, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.VerifyPeerCertificate != nil {
		t.Error("VerifyPeerCertificate should be nil without ClientPolicy")
	}
}

func TestNewServerTLSConfigWithClientCA(t *testing.T) {
	_, ca := generateCACert(t)

	t.Run("pool installed with verify-if-given default", func(t *testing.T) {
		cfg := testServerConfig()
		cfg.ClientCA = ca

		tlsCfg, _, err := NewServerTLSConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if tlsCfg.ClientCAs == nil {
			t.Fatal("the client CA pool is not installed")
		}
		if tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Errorf("ClientAuth = %v, want the VerifyClientCertIfGiven default", tlsCfg.ClientAuth)
		}
		if tlsCfg.VerifyPeerCertificate != nil {
			t.Error("VerifyPeerCertificate must stay nil: ClientCA verification is crypto/tls's, not armTLS")
		}
	})

	t.Run("explicit ClientAuth is kept", func(t *testing.T) {
		cfg := testServerConfig()
		cfg.ClientCA = ca
		cfg.ClientAuth = tls.RequireAndVerifyClientCert

		tlsCfg, _, err := NewServerTLSConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert kept", tlsCfg.ClientAuth)
		}
	})

	t.Run("ClientCA and ClientPolicy are mutually exclusive", func(t *testing.T) {
		// ClientPolicy admits a self-issued armTLS peer, which ClientCA exists
		// to refuse; combining them must be a construction-time error, not a
		// silently weaker listener.
		cfg := testServerConfig()
		cfg.ClientCA = ca
		cfg.ClientPolicy = &VerifyPolicy{}

		if _, _, err := NewServerTLSConfig(cfg); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err = %v, want the mutual-exclusion refusal", err)
		}
	})
}

func TestNewClientTLSConfig(t *testing.T) {
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{Policy: &VerifyPolicy{}})
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true (trust from hardware attestation)")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate is nil")
	}
	if tlsCfg.GetClientCertificate != nil {
		t.Error("GetClientCertificate should be nil without mTLS fields")
	}
}

func TestNewClientTLSConfigWithAttestation(t *testing.T) {
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{
		Policy:     &VerifyPolicy{AttestationApiURL: "http://unused.invalid"},
		Platform:   "sev-snp",
		AttestFunc: fakeAttestFunc,
		CertTTL:    1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is nil")
	}

	// Trigger client cert provisioning.
	cert, err := tlsCfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}

	if cert.PrivateKey == nil {
		t.Error("private key is nil")
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	requireARMTLSExtension(t, parsed)
}

func TestNewClientTLSConfigInvalidMTLS(t *testing.T) {
	// Platform without AttestFunc.
	_, _, err := NewClientTLSConfig(&ClientConfig{Platform: "sev-snp"})
	if err == nil {
		t.Error("expected error for Platform without AttestFunc")
	}

	// AttestFunc without Platform.
	_, _, err = NewClientTLSConfig(&ClientConfig{AttestFunc: fakeAttestFunc})
	if err == nil {
		t.Error("expected error for AttestFunc without Platform")
	}
}

func TestEndToEnd(t *testing.T) {
	serverTLS, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "attested")
	})
	go http.Serve(ln, mux)

	// Client skips PKI verification — in production, VerifyPeerCertificate
	// checks the armTLS extension. Here we just validate TLS plumbing.
	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}

	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := string(body); got != "attested\n" {
		t.Errorf("body = %q, want %q", got, "attested\n")
	}

	// Verify the server cert has armTLS extension.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	requireARMTLSExtension(t, conn.ConnectionState().PeerCertificates[0])
}

func TestMutualTLS(t *testing.T) {
	// Server presents armTLS cert and requires client armTLS cert.
	// We can't use VerifyPeerCertificate callbacks here because fake reports
	// lack valid AMD signatures. Instead we manually wire ClientAuth and
	// verify that both sides exchange certs with armTLS extensions.
	serverTLS, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	serverTLS.ClientAuth = tls.RequireAnyClientCert

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Capture the client cert as seen by the server.
	var clientCert *x509.Certificate
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if len(r.TLS.PeerCertificates) > 0 {
			clientCert = r.TLS.PeerCertificates[0]
		}
		mu.Unlock()
		fmt.Fprintln(w, "mutual")
	})
	go http.Serve(ln, mux)

	// Client presents its own armTLS cert.
	clientProvider := &SelfSignedProvider{
		Platform:   "sev-snp",
		AttestFunc: fakeAttestFunc,
		Opts:       &CertOptions{TTL: 1 * time.Hour},
	}
	clientState := &certState{provider: clientProvider}
	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientState.getOrProvision(info.Context())
		},
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}

	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Verify server cert has armTLS extension.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	requireARMTLSExtension(t, conn.ConnectionState().PeerCertificates[0])

	// Verify client cert (as seen by server) has armTLS extension.
	mu.Lock()
	defer mu.Unlock()
	if clientCert == nil {
		t.Fatal("server did not receive client certificate")
	}
	requireARMTLSExtension(t, clientCert)
}

func TestNewServerTLSConfigMissingPlatform(t *testing.T) {
	_, _, err := NewServerTLSConfig(&ServerConfig{
		AttestFunc: func(context.Context, string) (string, error) { return "", nil },
	})
	if err == nil {
		t.Error("expected error for missing platform")
	}
}

func TestNewServerTLSConfigMissingAttestFunc(t *testing.T) {
	_, _, err := NewServerTLSConfig(&ServerConfig{
		Platform: "sev-snp",
	})
	if err == nil {
		t.Error("expected error for missing AttestFunc")
	}
}

func TestTDXPlatformAcceptedAtConfigTime(t *testing.T) {
	// TDX is a supported platform end-to-end. Server + client configs must
	// build. Verification of a real TDX quote (VerifyAttestation) is
	// handled at handshake time; config-time is only the platform
	// allowlist gate.
	if _, _, err := NewServerTLSConfig(&ServerConfig{
		Platform:   "tdx",
		AttestFunc: fakeAttestFunc,
	}); err != nil {
		t.Errorf("expected TDX server config to build, got: %v", err)
	}
	if _, _, err := NewClientTLSConfig(&ClientConfig{
		Policy:     &VerifyPolicy{AttestationApiURL: "http://unused.invalid"},
		Platform:   "tdx",
		AttestFunc: fakeAttestFunc,
	}); err != nil {
		t.Errorf("expected TDX client config to build, got: %v", err)
	}
}

func TestConcurrentCertProvisioning(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount.Add(1)
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 10
	certs := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			certs[idx], errs[idx] = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
		}(i)
	}
	wg.Wait()

	// All must succeed.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	// All must get the same cert (pointer equality).
	for i := 1; i < goroutines; i++ {
		if certs[i] != certs[0] {
			t.Errorf("goroutine %d got different cert pointer", i)
		}
	}

	// AttestFunc should be called exactly once.
	if got := callCount.Load(); got != 1 {
		t.Errorf("AttestFunc called %d times, want 1", got)
	}
}

func TestCertRotationTiming(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	// Whole seconds: X.509 encodes validity at second granularity, so a
	// sub-second TTL truncates to an already-expired NotAfter and would trip
	// the hard expiry stop instead of exercising rotation.
	cfg.CertTTL = 4 * time.Second
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount.Add(1)
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First call provisions synchronously.
	cert1, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 attestation call, got %d", callCount.Load())
	}

	// Wait past rotation window (50% of 4s = 2s) but well short of expiry.
	time.Sleep(2100 * time.Millisecond)

	// This call triggers background rotation but returns the OLD cert.
	certOld, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if certOld != cert1 {
		t.Error("expected old cert returned during background rotation")
	}

	// Poll until the rotated cert is served. callCount bumps when the
	// background attestation *starts*, but the new cert is stored only after
	// Provision returns, so waiting on the counter races the store. Poll the
	// observable outcome instead — the cert actually changing.
	deadline := time.After(2 * time.Second)
	for {
		cert2, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if cert2 != cert1 {
			verifier := mockapi.New(t)
			verifier.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(make([]byte, SNPMeasurementSize))))
			if _, err := VerifyCert(cert2.Leaf, &VerifyPolicy{AttestationApiURL: verifier.URL()}, nil); err != nil {
				t.Fatalf("renewed certificate failed attestation verification: %v", err)
			}
			if len(verifier.VerifyRequests()) != 1 {
				t.Fatal("renewed certificate bypassed attestation verification")
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for background rotation to serve the new cert")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestBackgroundRotationNonBlocking(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	// Whole seconds: a sub-second TTL truncates to an already-expired
	// NotAfter (X.509 second granularity) and would force the synchronous
	// fail-closed path this test must not take.
	cfg.CertTTL = 4 * time.Second
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		n := callCount.Add(1)
		if n > 1 {
			// Slow rotation to prove callers aren't blocked.
			time.Sleep(200 * time.Millisecond)
		}
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First call: fast, synchronous provisioning.
	_, err = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait past rotation window (50% of 4s) but well short of expiry.
	time.Sleep(2100 * time.Millisecond)

	// Trigger background rotation (slow: 200ms).
	_, _ = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})

	// Concurrent calls must all return immediately (not blocked by 200ms rotation).
	const goroutines = 10
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// All calls should complete well under 200ms (the rotation time).
	if elapsed > 100*time.Millisecond {
		t.Errorf("concurrent GetCertificate took %v, expected <100ms (non-blocking)", elapsed)
	}
}

func TestCertManagerWarmUp(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount.Add(1)
		return fakeAttestFunc(ctx, customData)
	}

	_, mgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Before warm-up: not ready.
	if mgr.CertReady() {
		t.Error("CertReady should be false before WarmUp")
	}

	// Warm up.
	if err := mgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// After warm-up: ready.
	if !mgr.CertReady() {
		t.Error("CertReady should be true after WarmUp")
	}

	// AttestFunc should have been called exactly once.
	if got := callCount.Load(); got != 1 {
		t.Errorf("AttestFunc called %d times, want 1", got)
	}
}

func TestCertManagerRotationFailCallback(t *testing.T) {
	var failCount atomic.Int32
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.CertTTL = 4 * time.Second
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		n := callCount.Add(1)
		if n > 1 {
			return "", fmt.Errorf("simulated failure")
		}
		return fakeAttestFunc(ctx, customData)
	}

	_, mgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetOnRotationFail(func() { failCount.Add(1) })

	// Warm up successfully.
	if err := mgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Trigger background rotation (which will fail).
	state := mgr.state
	if state.rotating.CompareAndSwap(false, true) {
		state.backgroundProvision(context.Background(), state.provider, state.revision)
	}

	// The failure callback should have been called.
	if got := failCount.Load(); got != 1 {
		t.Errorf("rotation failure callback called %d times, want 1", got)
	}
}

// --- Helpers for dual-verify and swap-provider tests ---

type mockProvider struct {
	cert *tls.Certificate
	ttl  time.Duration
}

func (m *mockProvider) Provision(_ context.Context) (*tls.Certificate, time.Duration, error) {
	return m.cert, m.ttl, nil
}

func generateSimpleCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func generateCACert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}
	return caKey, caCert
}

func TestSwapProvider(t *testing.T) {
	// Create a server TLS config with fakeAttestFunc.
	cfg := testServerConfig()
	tlsCfg, certMgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Warm up to provision the first cert.
	if err := certMgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Get the original cert.
	origCert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock provider with a different cert.
	newCert := generateSimpleCert(t)
	mock := &mockProvider{cert: newCert, ttl: 1 * time.Hour}

	// Swap the provider.
	if err := certMgr.SwapProvider(context.Background(), mock); err != nil {
		t.Fatal(err)
	}

	// Get cert from GetCertificate — should be the new one.
	gotCert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if gotCert == origCert {
		t.Error("expected different cert after SwapProvider")
	}
	if gotCert != newCert {
		t.Error("expected GetCertificate to return the mock provider's cert")
	}

	// CertReady should be true.
	if !certMgr.CertReady() {
		t.Error("CertReady should be true after SwapProvider")
	}
}

func TestSwapProvider_ConcurrentAccess(t *testing.T) {
	// Create a server TLS config with fakeAttestFunc.
	cfg := testServerConfig()
	tlsCfg, certMgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Warm up to provision the first cert.
	if err := certMgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Prepare the new cert for the swap.
	newCert := generateSimpleCert(t)
	mock := &mockProvider{cert: newCert, ttl: 1 * time.Hour}

	const goroutines = 10
	const iterations = 100
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	// Start goroutines that continuously call GetCertificate.
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			for range iterations {
				_, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					errs[idx] = err
					return
				}
			}
		}(i)
	}

	// In the main goroutine, swap the provider while readers are active.
	if err := certMgr.SwapProvider(context.Background(), mock); err != nil {
		t.Fatalf("SwapProvider failed: %v", err)
	}

	wg.Wait()

	// No goroutine should have encountered an error.
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// Eventually GetCertificate should return the new cert.
	gotCert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if gotCert != newCert {
		t.Error("expected GetCertificate to return the new cert after SwapProvider")
	}
}

// errProvider always fails provisioning.
type errProvider struct{}

func (errProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	return nil, 0, fmt.Errorf("provision refused")
}

// deadlineProvider records the context deadline it was provisioned under.
type deadlineProvider struct {
	cert     *tls.Certificate
	deadline time.Time
	ok       bool
}

func (p *deadlineProvider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	p.deadline, p.ok = ctx.Deadline()
	return p.cert, time.Hour, nil
}

// caSignedLeafDER issues a leaf certificate signed by the given CA.
func caSignedLeafDER(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(500),
		Subject:      pkix.Name{CommonName: "peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// rotateAtOf reads the rotation deadline under the state lock.
func rotateAtOf(s *certState) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rotateAt
}

// requireRotateAtNear asserts rotateAt falls in (start+lo, start+hi).
func requireRotateAtNear(t *testing.T, rotateAt, start time.Time, lo, hi time.Duration) {
	t.Helper()
	if rotateAt.Before(start.Add(lo)) || rotateAt.After(time.Now().Add(hi)) {
		t.Fatalf("rotateAt = %v, want within (%v, %v) of %v", rotateAt, lo, hi, start)
	}
}

func TestCertStateCertExpiry(t *testing.T) {
	t.Run("no cert yet", func(t *testing.T) {
		s := &certState{}
		if got := s.CertExpiry(); !got.IsZero() {
			t.Fatalf("CertExpiry = %v, want zero time", got)
		}
	})

	t.Run("cert without leaf", func(t *testing.T) {
		s := &certState{cert: &tls.Certificate{}}
		if got := s.CertExpiry(); !got.IsZero() {
			t.Fatalf("CertExpiry = %v, want zero time", got)
		}
	})

	t.Run("provisioned cert", func(t *testing.T) {
		cert := generateSimpleCert(t)
		s := &certState{provider: &mockProvider{cert: cert, ttl: time.Hour}}
		if _, err := s.getOrProvision(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := s.CertExpiry(); !got.Equal(cert.Leaf.NotAfter) {
			t.Fatalf("CertExpiry = %v, want %v", got, cert.Leaf.NotAfter)
		}
	})
}

func TestCertStateProvisionFailure(t *testing.T) {
	s := &certState{provider: errProvider{}}
	if _, err := s.getOrProvision(context.Background()); err == nil {
		t.Fatal("expected provisioning error")
	}
	if s.CertReady() {
		t.Fatal("CertReady = true after failed provisioning")
	}
}

func TestCertStateRotateAtHalvesDefaultTTL(t *testing.T) {
	// Provider reports no TTL: the configured default applies, halved.
	s := &certState{
		provider:   &mockProvider{cert: generateSimpleCert(t), ttl: 0},
		defaultTTL: 10 * time.Hour,
	}
	start := time.Now()
	if _, err := s.getOrProvision(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRotateAtNear(t, rotateAtOf(s), start, 4*time.Hour, 6*time.Hour)
}

func TestBackgroundProvisionRotationTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		lo, hi  time.Duration
	}{
		{"default 30s", 0, 20 * time.Second, 40 * time.Second},
		{"configured", 5 * time.Minute, 4 * time.Minute, 6 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &deadlineProvider{cert: generateSimpleCert(t)}
			s := &certState{provider: p, rotationTimeout: tt.timeout}
			start := time.Now()
			s.backgroundProvision(context.Background(), p, s.revision)
			if !p.ok {
				t.Fatal("provisioning context has no deadline")
			}
			if d := p.deadline.Sub(start); d < tt.lo || d > tt.hi {
				t.Fatalf("provisioning deadline in %v, want within (%v, %v)", d, tt.lo, tt.hi)
			}
		})
	}
}

func TestBackgroundProvisionRotateAtHalvesDefaultTTL(t *testing.T) {
	cert := generateSimpleCert(t)
	p := &mockProvider{cert: cert, ttl: 0}
	s := &certState{provider: p, defaultTTL: 10 * time.Hour}
	start := time.Now()
	s.backgroundProvision(context.Background(), p, s.revision)
	s.mu.RLock()
	got := s.cert
	s.mu.RUnlock()
	if got != cert {
		t.Fatal("background provisioning did not install the new cert")
	}
	requireRotateAtNear(t, rotateAtOf(s), start, 4*time.Hour, 6*time.Hour)
}

func TestBackgroundProvisionDiscardsStaleProvider(t *testing.T) {
	current := &mockProvider{cert: generateSimpleCert(t), ttl: time.Hour}
	stale := &mockProvider{cert: generateSimpleCert(t), ttl: time.Hour}
	s := &certState{provider: current}
	s.revision = 1
	s.backgroundProvision(context.Background(), stale, 0)
	s.mu.RLock()
	got := s.cert
	s.mu.RUnlock()
	if got != nil {
		t.Fatal("stale provider's cert was installed after provider swap")
	}
}

func TestEffectiveTTL(t *testing.T) {
	tests := []struct {
		name       string
		defaultTTL time.Duration
		want       time.Duration
	}{
		{"configured", 10 * time.Hour, 10 * time.Hour},
		{"unset falls back to 24h", 0, 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &certState{defaultTTL: tt.defaultTTL}
			if got := s.effectiveTTL(); got != tt.want {
				t.Fatalf("effectiveTTL = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSwapProviderFailureKeepsProvider(t *testing.T) {
	current := &mockProvider{cert: generateSimpleCert(t), ttl: time.Hour}
	s := &certState{provider: current}
	if _, err := s.getOrProvision(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapProvider(context.Background(), errProvider{}); err == nil {
		t.Fatal("expected SwapProvider error")
	}
	s.mu.RLock()
	provider, cert := s.provider, s.cert
	s.mu.RUnlock()
	if provider != CertProvider(current) {
		t.Fatal("failed swap replaced the provider")
	}
	if cert != current.cert {
		t.Fatal("failed swap replaced the certificate")
	}
}

func TestSwapProviderRotateAtHalvesDefaultTTL(t *testing.T) {
	next := &mockProvider{cert: generateSimpleCert(t), ttl: 0}
	s := &certState{provider: errProvider{}, defaultTTL: 10 * time.Hour}
	start := time.Now()
	if err := s.SwapProvider(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	requireRotateAtNear(t, rotateAtOf(s), start, 4*time.Hour, 6*time.Hour)
}

// A chain-signed leaf is refused on the evidence path: an armTLS peer proves
// itself with key-bound evidence on a self-issued certificate, and no mesh CA
// the process holds changes that.
func TestChainSignedPeerIsRefusedOnTheServerEvidencePath(t *testing.T) {
	caKey, caCert := generateCACert(t)
	cfg := testServerConfig()
	cfg.ClientPolicy = &VerifyPolicy{AttestationApiURL: "http://unused.invalid"}
	server, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.VerifyPeerCertificate([][]byte{caSignedLeafDER(t, caKey, caCert)}, nil); err == nil {
		t.Fatal("a chain-signed peer was accepted on the evidence path")
	}
}

func TestChainSignedPeerIsRefusedOnTheClientEvidencePath(t *testing.T) {
	caKey, caCert := generateCACert(t)
	client, _, err := NewClientTLSConfig(&ClientConfig{
		Policy: &VerifyPolicy{AttestationApiURL: "http://unused.invalid"},
		CertProvider: &mockProvider{
			cert: generateSimpleCert(t),
			ttl:  time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyPeerCertificate([][]byte{caSignedLeafDER(t, caKey, caCert)}, nil); err == nil {
		t.Fatal("a chain-signed peer was accepted on the evidence path")
	}
}

// A listener authenticates its peers one way: a client policy admits the
// self-issued peer a client CA exists to refuse.
func TestServerRefusesBothPeerAuthentications(t *testing.T) {
	_, caCert := generateCACert(t)
	cfg := testServerConfig()
	cfg.ClientCA = caCert
	cfg.ClientPolicy = &VerifyPolicy{AttestationApiURL: "http://unused.invalid"}
	if _, _, err := NewServerTLSConfig(cfg); err == nil {
		t.Fatal("a listener was configured with both a client CA and a client policy")
	}
}

// The evidence path requires the purpose the peer's role needs, so a
// self-issued leaf permitting neither is refused before any attestation-api
// round-trip.
func TestEvidencePathRequiresTheRolePurpose(t *testing.T) {
	stub := mockapi.New(t)
	attested := attestedCertWithPurposes(t)
	for name, purpose := range map[string]x509.ExtKeyUsage{
		"server": x509.ExtKeyUsageServerAuth,
		"client": x509.ExtKeyUsageClientAuth,
	} {
		t.Run(name, func(t *testing.T) {
			cb := verifyPeerCallback(&VerifyPolicy{AttestationApiURL: stub.URL()}, purpose)
			if err := cb([][]byte{attested}, nil); err == nil {
				t.Fatal("a leaf permitting no purpose was accepted")
			}
		})
	}
	if got := len(stub.VerifyRequests()); got != 0 {
		t.Fatalf("a leaf with no purpose consumed %d attestation-api call(s), want 0", got)
	}
}

// attestedCertWithPurposes mints a self-issued armTLS certificate carrying
// genuine evidence and the given extended key usages.
func attestedCertWithPurposes(t *testing.T, purposes ...x509.ExtKeyUsage) []byte {
	t.Helper()
	key, att := testKeyAndAttestation(t)
	ext, err := MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(640),
		Subject:         pkix.Name{CommonName: "purposeless-armtls"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtKeyUsage:     purposes,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerifyPeerCallback(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(measurement)))
	policy := &VerifyPolicy{
		AttestationApiURL: stub.URL(),
		Policy:            remote.Policy{Measurements: [][]byte{measurement}},
	}
	cb := verifyPeerCallback(policy, x509.ExtKeyUsageServerAuth)

	_, _, attested := testAttestedCert(t, nil)
	plain := generateSimpleCert(t)

	tests := []struct {
		name     string
		rawCerts [][]byte
		wantErr  bool
	}{
		{"no certs", nil, true},
		{"garbage cert", [][]byte{{0x01, 0x02}}, true},
		{"unattested cert", [][]byte{plain.Leaf.Raw}, true},
		{"attested cert", [][]byte{attested.Raw}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cb(tt.rawCerts, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verify err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewVerifyingHTTPClient(t *testing.T) {
	if _, err := NewVerifyingHTTPClient(Pins{}, ""); err == nil {
		t.Fatal("expected error for empty attestation-api URL")
	}

	client, err := NewVerifyingHTTPClient(Pins{}, "http://127.0.0.1:8400")
	if err != nil {
		t.Fatal(err)
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if tr.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 10s", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 30s", tr.IdleConnTimeout)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", tr.TLSClientConfig.MinVersion)
	}
	if tr.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate is nil: peer attestation would not be checked")
	}
}
