package join

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// testHandler builds a releaseHandler over a fake attestation-api and a token
// path inside a temp dir (file not written unless token != "").
func testHandler(t *testing.T, api *fakeAPI, token string) *releaseHandler {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "agent-token")
	if token != "" {
		if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(tokenPath), "token"), []byte(testCA+"::server:privileged-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &releaseHandler{
		policy:        testPolicy(t, teetypes.PlatformTDX, testOperator, api.URL),
		server:        testServerDoc(teetypes.PlatformTDX, testOperator),
		passwordKey:   writePasswordKey(t, filepath.Dir(tokenPath)),
		loadKey:       readPasswordKey,
		tokenPath:     tokenPath,
		verifyTimeout: 5 * time.Second,
		verifySlots:   make(chan struct{}, maxConcurrentVerifications),
		logger:        slog.Default(),
	}
}

// testJoin is the default fixture agent's /join request.
func testJoin(t *testing.T) []byte {
	t.Helper()
	return joinBody(t, testServerDoc(teetypes.PlatformTDX, testOperator), testAgentName, testOperatorKey, nil)
}

// doTLS runs a request through the handler with the given peer certs attached
// as TLS state.
func doTLS(h http.Handler, method, path string, body []byte, peers []*x509.Certificate) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: peers}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestReleaseHandler(t *testing.T) {
	okAPI := func(t *testing.T) *fakeAPI {
		return newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
	}

	t.Run("attested authorized agent gets the token", func(t *testing.T) {
		h := testHandler(t, okAPI(t), testToken+"\n")
		rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
		}
		var resp tokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Token != testToken {
			t.Errorf("token = %q, want trimmed staged token", resp.Token)
		}
		if resp.NodePassword != nodePasswordFor(t, h, testAgentName) {
			t.Errorf("node password is not the one derived for %s", testAgentName)
		}
	})

	t.Run("policy mismatch denied", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, operatorKey(t))))
		h := testHandler(t, api, testToken)
		rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("no client certificate denied", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodPost, "/join", testJoin(t), nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("unattested certificate denied", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{plainLeaf(t)})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("token not on disk yet", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "")
		rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})

	t.Run("empty token file is not ready", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "\n")
		rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})

	t.Run("token appearing later is served without restart", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "")
		leaf := []*x509.Certificate{attestedLeaf(t, tdxEnvelope)}
		if rec := doTLS(h, http.MethodPost, "/join", testJoin(t), leaf); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("first status = %d, want 503", rec.Code)
		}
		if err := os.WriteFile(h.tokenPath, []byte(testCA+"::node:late-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		if rec := doTLS(h, http.MethodPost, "/join", testJoin(t), leaf); rec.Code != http.StatusOK {
			t.Fatalf("second status = %d, want 200", rec.Code)
		}
	})

	t.Run("server token is never released", func(t *testing.T) {
		h := testHandler(t, okAPI(t), testCA+"::server:secret")
		rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})

	t.Run("wrong path", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodPost, "/release-credential", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodGet, "/join", nil, []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})
}

func TestReleaseHandlerBoundsConcurrentVerification(t *testing.T) {
	entered := make(chan struct{}, maxConcurrentVerifications)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }

	api := newFakeAPI(t, func(int, remote.VerifyRequest) remote.VerifyResponse {
		entered <- struct{}{}
		<-release
		return verifyResp(teetypes.PlatformTDX, testOperator)
	})
	t.Cleanup(unblock)
	h := testHandler(t, api, testToken)
	leaf := []*x509.Certificate{attestedLeaf(t, tdxEnvelope)}
	body := testJoin(t)

	var wg sync.WaitGroup
	statuses := make(chan int, maxConcurrentVerifications)
	for range maxConcurrentVerifications {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- doTLS(h, http.MethodPost, "/join", body, leaf).Code
		}()
	}

	for range maxConcurrentVerifications {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("verification requests did not reach the configured limit")
		}
	}

	overflow := doTLS(h, http.MethodPost, "/join", testJoin(t), leaf)
	if overflow.Code != http.StatusServiceUnavailable {
		t.Errorf("overflow status = %d, want 503", overflow.Code)
	}
	if got := api.verifyCalls.Load(); got != maxConcurrentVerifications {
		t.Errorf("verify calls = %d, want %d", got, maxConcurrentVerifications)
	}

	unblock()
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Errorf("admitted request status = %d, want 200", status)
		}
	}
}

func TestIsSecureAgentToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "agent token", token: testToken, want: true},
		{name: "server token", token: testCA + "::server:secret", want: false},
		{name: "node marker inside server secret", token: testCA + "::server:secret::node:forged", want: false},
		{name: "missing secret", token: testCA + "::node:", want: false},
		{name: "short token", token: "secret", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSecureAgentToken(tt.token); got != tt.want {
				t.Errorf("isSecureAgentToken(%q) = %t, want %t", tt.token, got, tt.want)
			}
		})
	}
}

// releaseConfig returns a ReleaseConfig RunRelease can fully start from.
func releaseConfig(t *testing.T) ReleaseConfig {
	t.Helper()
	api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
	dir := t.TempDir()
	return ReleaseConfig{
		ListenAddr:         "127.0.0.1:0",
		AttestationAPIURL:  api.URL,
		Platform:           "tdx",
		MeasurementsConfig: policyFile(t, teetypes.PlatformTDX, policyEntry(t, teetypes.PlatformTDX, testOperator)),
		TokenPath:          filepath.Join(dir, "agent-token"),
		VerifyTimeout:      5 * time.Second,
		LaunchConfig:       writeStagedServer(t, dir, testServerDoc(teetypes.PlatformTDX, testOperator)),
		NodePasswordKey:    writePasswordKey(t, dir),
	}
}

func TestRunReleaseStartupErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(t *testing.T) ReleaseConfig
	}{
		{"platform required", func(t *testing.T) ReleaseConfig { return ReleaseConfig{Platform: ""} }},
		{"server launch document required", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			cfg.LaunchConfig = filepath.Join(t.TempDir(), "missing.json")
			return cfg
		}},
		{"agent launch document refused", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			doc := testServerDoc(teetypes.PlatformTDX, testOperator)
			doc.Role = launchconfig.Agent
			cfg.LaunchConfig = writeStagedServer(t, t.TempDir(), doc)
			return cfg
		}},
		{"node password key required", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			cfg.NodePasswordKey = ""
			return cfg
		}},
		{"verify-timeout must be positive", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			cfg.VerifyTimeout = 0
			return cfg
		}},
		{"attestation-api down at provisioning", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			cfg.AttestationAPIURL = "http://127.0.0.1:1"
			return cfg
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := RunRelease(context.Background(), tc.cfg(t)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// probeCert builds a self-signed tls.Certificate the readiness probe presents
// as its client cert. The handler denies it (no armTLS extension); any HTTP
// response at all proves the server is accepting requests.
func probeCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestRunReleaseServesAndShutsDown(t *testing.T) {
	cfg := releaseConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg.ListenAddr = ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runRelease(ctx, cfg, ln) }()

	// The injected listener is bound before runRelease starts, so a raw TCP
	// dial succeeds (accept backlog) while the startup attestation ladder is
	// still running and cancel would race it. Probe with a full HTTPS request
	// instead: a response only comes back once ServeTLS is accepting.
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{probeCert(t)},
		}},
	}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Post("https://"+cfg.ListenAddr+"/join", "application/json", bytes.NewReader(testJoin(t)))
		if err == nil {
			resp.Body.Close()
			// The serving cert's validity window is the replay bound for a
			// stolen leaf key; pin it so a TTL change can't widen it silently.
			leaf := resp.TLS.PeerCertificates[0]
			if window := leaf.NotAfter.Sub(leaf.NotBefore); window > releaseServerCertTTL+time.Minute {
				t.Errorf("serving cert validity window = %s, want <= %s", window, releaseServerCertTTL)
			}
			break
		}
		select {
		case err := <-done:
			t.Fatalf("RunRelease exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never answered a request: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunRelease after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunRelease did not return after context cancel")
	}
}

func TestRunReleaseListenError(t *testing.T) {
	cfg := releaseConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg.ListenAddr = ln.Addr().String() // already taken

	done := make(chan error, 1)
	go func() { done <- RunRelease(context.Background(), cfg) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected bind error, got nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunRelease did not surface the bind error")
	}
}

func TestReleaseRefusesPrivilegedTokenAliases(t *testing.T) {
	for _, tc := range []struct {
		name, agent, server string
		symlink             bool
		accept              bool
	}{
		{name: "distinct agent", agent: testToken, server: testCA + "::server:privileged-secret", accept: true},
		{name: "default symlink", server: testCA + "::server:privileged-secret", symlink: true},
		{name: "same secret rewritten role", agent: testCA + "::node:privileged-secret", server: testCA + "::server:privileged-secret"},
		{name: "missing privileged token", agent: testToken},
		{name: "wrong privileged role", agent: testToken, server: testCA + "::node:other"},
		{name: "different CA pin", agent: testToken, server: "K10" + strings.Repeat("dc", 32) + "::server:other"},
		{name: "short hash", agent: "K10cafe::node:secret", server: testCA + "::server:other"},
		{name: "nonhex hash", agent: "K10" + strings.Repeat("zz", 32) + "::node:secret", server: testCA + "::server:other"},
		{name: "newline secret", agent: testCA + "::node:secret\nother", server: testCA + "::server:other"},
		{name: "oversized token", agent: testCA + "::node:" + strings.Repeat("a", maxTokenRespBytes), server: testCA + "::server:other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "agent-token")
			if tc.server != "" {
				if err := os.WriteFile(filepath.Join(dir, "token"), []byte(tc.server), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.symlink {
				if err := os.Symlink("token", path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, []byte(tc.agent), 0600); err != nil {
					t.Fatal(err)
				}
			}
			token, err := readAgentToken(path)
			if (err == nil) != tc.accept {
				t.Fatalf("err=%v accept=%v", err, tc.accept)
			}
			if tc.accept && token != testToken {
				t.Fatal("wrong agent token")
			}
		})
	}
}

func TestReleaseVerificationTimeout(t *testing.T) {
	unblock := make(chan struct{})
	api := newFakeAPI(t, func(_ int, _ remote.VerifyRequest) remote.VerifyResponse {
		<-unblock
		return verifyResp(teetypes.PlatformTDX, testOperator)
	})
	defer close(unblock)
	h := testHandler(t, api, testToken)
	h.verifyTimeout = 20 * time.Millisecond
	start := time.Now()
	rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	if time.Since(start) > time.Second {
		t.Fatal("request verification did not obey configured bound")
	}
}

// Even a replayed certificate whose evidence the verifier accepts cannot fetch
// the token without proving possession of that certificate's private key in TLS.
func TestReleaseRequiresAttestedPrivateKeyPossession(t *testing.T) {
	key, _, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := armtls.CreateAttestedCert(key, &armtls.Attestation{Family: armtls.TEETypeTDX, Report: []byte(tdxEnvelope)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		private *ecdsa.PrivateKey
		accept  bool
	}{{"matching key", key, true}, {"replayed certificate", wrong, false}} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
			srv := httptest.NewUnstartedServer(testHandler(t, api, testToken))
			srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
			srv.StartTLS()
			defer srv.Close()
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: tc.private}}}}}
			defer client.CloseIdleConnections()
			resp, err := client.Post(srv.URL+"/join", "application/json", bytes.NewReader(testJoin(t)))
			if resp != nil {
				defer resp.Body.Close()
			}
			if tc.accept {
				if err != nil || resp.StatusCode != http.StatusOK {
					t.Fatalf("valid possession denied: response=%v err=%v", resp, err)
				}
			} else {
				if err == nil {
					t.Fatal("replayed certificate accepted without its private key")
				}
				if api.verifyCalls.Load() != 0 {
					t.Fatal("handler reached without proof of private key possession")
				}
			}
		})
	}
}

// Stalled handshakes release their slot quickly, while the write deadline,
// which restarts after the headers, still covers the handler's verification.
func TestReleaseServerDeadlines(t *testing.T) {
	const verifyTimeout = 20 * time.Second
	srv := newReleaseServer(http.NotFoundHandler(), &tls.Config{}, verifyTimeout)
	if handshake := min(srv.ReadHeaderTimeout, srv.WriteTimeout); handshake != handshakeTimeout {
		t.Fatalf("handshake deadline %s, want %s", handshake, handshakeTimeout)
	}
	if srv.WriteTimeout <= verifyTimeout {
		t.Fatalf("write deadline %s leaves no room after a %s verification", srv.WriteTimeout, verifyTimeout)
	}
}

// nodePasswordFor is the password h derives for name under its key.
func nodePasswordFor(t *testing.T, h *releaseHandler, name string) string {
	t.Helper()
	key, err := h.loadKey(h.passwordKey)
	if err != nil {
		t.Fatal(err)
	}
	return launchconfig.NodePassword(key, name)
}

func releasedPassword(t *testing.T, h *releaseHandler, body []byte) string {
	t.Helper()
	rec := doTLS(h, http.MethodPost, "/join", body, []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.NodePassword
}

// An agent gets the password for the name its signed document carries, the
// same one on every enrollment and across a release restart, and never
// another node's.
func TestReleaseNodePasswordFollowsTheSignedName(t *testing.T) {
	api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
	h := testHandler(t, api, testToken)
	server := h.server
	x := releasedPassword(t, h, joinBody(t, server, "agent-x", testOperatorKey, nil))
	if x != nodePasswordFor(t, h, "agent-x") {
		t.Fatal("agent-x did not get agent-x's password")
	}
	if again := releasedPassword(t, h, joinBody(t, server, "agent-x", testOperatorKey, nil)); again != x {
		t.Fatal("a second enrollment of agent-x got another password")
	}
	if y := releasedPassword(t, h, joinBody(t, server, "agent-y", testOperatorKey, nil)); y == x {
		t.Fatal("an agent whose document names agent-y obtained agent-x's password")
	}
	// A restarted release reads the same RAM key, so the password is stable.
	restarted := *h
	restarted.verifySlots = make(chan struct{}, maxConcurrentVerifications)
	if after := releasedPassword(t, &restarted, joinBody(t, server, "agent-x", testOperatorKey, nil)); after != x {
		t.Fatal("a release restart changed agent-x's password")
	}
	// The server's own password derives from the same key, and no agent
	// document can claim it.
	if x == nodePasswordFor(t, h, testServerName) {
		t.Fatal("agent-x shares the server's password")
	}
}

func TestReleaseRefusesUnauthenticatedNames(t *testing.T) {
	otherKey, otherPEM := newLaunchKey()
	for _, tc := range []struct {
		name   string
		key    *ecdsa.PrivateKey
		mutate func(*launchconfig.Document)
		body   []byte
	}{
		{name: "no node name", key: testOperatorKey, mutate: func(d *launchconfig.Document) { d.Node.Name = "" }},
		{name: "names the server", key: testOperatorKey, mutate: func(d *launchconfig.Document) { d.Node.Name = testServerName }},
		{name: "signed by the server key", key: testServerLaunchKey},
		{name: "signed by an unauthorized key", key: otherKey, mutate: func(d *launchconfig.Document) {
			d.AgentOperatorPublicKeys = []string{string(otherPEM)}
		}},
		{name: "another cluster", key: testOperatorKey, mutate: func(d *launchconfig.Document) { d.ClusterID = "cluster-two" }},
		{name: "another server", key: testOperatorKey, mutate: func(d *launchconfig.Document) {
			d.Server.OperatorPublicKey = string(otherPEM)
		}},
		{name: "server role", key: testOperatorKey, mutate: func(d *launchconfig.Document) { d.Role = launchconfig.Server }},
		{name: "unsigned", body: []byte(`{"document":"","signature":""}`)},
		{name: "unknown field", body: []byte(`{"document":"","signature":"","name":"agent-x"}`)},
		{name: "not JSON", body: []byte(`agent-x`)},
		{name: "oversized", body: bytes.Repeat([]byte(" "), maxJoinRequestBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
			h := testHandler(t, api, testToken)
			body := tc.body
			if body == nil {
				body = joinBody(t, h.server, "agent-x", tc.key, tc.mutate)
			}
			rec := doTLS(h, http.MethodPost, "/join", body, []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if api.verifyCalls.Load() != 0 {
				t.Fatal("a refused document still cost an attestation call")
			}
		})
	}
}

// Two authorized agent keys: a peer measured under one cannot enroll with a
// document the other signed.
func TestReleaseBindsTheDocumentKeyToTheAttestedKey(t *testing.T) {
	keyB, pemB := newLaunchKey()
	for _, tc := range []struct {
		name   string
		signer *ecdsa.PrivateKey
		accept bool
	}{{"same key", testOperatorKey, true}, {"other authorized key", keyB, false}} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
			h := testHandler(t, api, testToken)
			a, b := policyEntry(t, teetypes.PlatformTDX, testOperator), policyEntry(t, teetypes.PlatformTDX, pemB)
			b.Name = "authorized-b"
			policy, err := loadPeerPolicy(policyFile(t, teetypes.PlatformTDX, a, b), "tdx", api.URL, 5*time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			h.policy = policy
			h.server = testServerDoc(teetypes.PlatformTDX, testOperator, pemB)
			rec := doTLS(h, http.MethodPost, "/join", joinBody(t, h.server, "agent-x", tc.signer, nil), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
			if want := map[bool]int{true: http.StatusOK, false: http.StatusForbidden}[tc.accept]; rec.Code != want {
				t.Fatalf("status = %d, want %d", rec.Code, want)
			}
		})
	}
}

func TestReleaseWithoutPasswordKeyIsNotReady(t *testing.T) {
	api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
	h := testHandler(t, api, testToken)
	h.passwordKey = filepath.Join(t.TempDir(), "missing")
	rec := doTLS(h, http.MethodPost, "/join", testJoin(t), []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
