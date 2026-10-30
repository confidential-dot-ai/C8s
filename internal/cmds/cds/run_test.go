package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestCompilePattern(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		re, err := compilePattern("--x", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if re != nil {
			t.Fatalf("empty pattern should yield nil regexp, got %v", re)
		}
	})

	t.Run("valid compiles", func(t *testing.T) {
		re, err := compilePattern("--x", `^a.*z$`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if re == nil || !re.MatchString("abz") {
			t.Fatalf("expected compiled pattern matching abz, got %v", re)
		}
	})

	t.Run("invalid returns error", func(t *testing.T) {
		if _, err := compilePattern("--x", "("); err == nil {
			t.Fatal("expected error for invalid regex, got nil")
		}
	})
}

func TestNormalizeHTTPServerConfig_FillsZeroDefaults(t *testing.T) {
	got := normalizeHTTPServerConfig(config{})
	if got.readTimeout != defaultHTTPReadTimeout {
		t.Errorf("readTimeout = %v, want %v", got.readTimeout, defaultHTTPReadTimeout)
	}
	if got.readHeaderTimeout != defaultHTTPReadHeaderTimeout {
		t.Errorf("readHeaderTimeout = %v, want %v", got.readHeaderTimeout, defaultHTTPReadHeaderTimeout)
	}
	if got.writeTimeout != defaultHTTPWriteTimeout {
		t.Errorf("writeTimeout = %v, want %v", got.writeTimeout, defaultHTTPWriteTimeout)
	}
	if got.idleTimeout != defaultHTTPIdleTimeout {
		t.Errorf("idleTimeout = %v, want %v", got.idleTimeout, defaultHTTPIdleTimeout)
	}
	if got.maxHeaderBytes != defaultHTTPMaxHeaderBytes {
		t.Errorf("maxHeaderBytes = %d, want %d", got.maxHeaderBytes, defaultHTTPMaxHeaderBytes)
	}
}

func TestNormalizeHTTPServerConfig_PreservesNonZero(t *testing.T) {
	in := config{
		readTimeout:       time.Second,
		readHeaderTimeout: 2 * time.Second,
		writeTimeout:      3 * time.Second,
		idleTimeout:       4 * time.Second,
		maxHeaderBytes:    99,
	}
	got := normalizeHTTPServerConfig(in)
	if got.readTimeout != in.readTimeout ||
		got.readHeaderTimeout != in.readHeaderTimeout ||
		got.writeTimeout != in.writeTimeout ||
		got.idleTimeout != in.idleTimeout ||
		got.maxHeaderBytes != in.maxHeaderBytes {
		t.Fatalf("normalizeHTTPServerConfig altered non-zero config: got %+v, want %+v", got, in)
	}
}

// operatorKeyPair generates an operator EC key and returns it with the PEM
// bundle pinning its public half, as a CDS configuration carries it.
func operatorKeyPair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen operator key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal operator key: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// operatorKeysPEM is a PEM bundle with one EC public key.
func operatorKeysPEM(t *testing.T) []byte {
	t.Helper()
	_, pemBytes := operatorKeyPair(t)
	return pemBytes
}

// newHealthyAttestationApi returns an httptest server that answers every path
// with a healthy JSON response, enough for readiness checks during run().
func newHealthyAttestationApi(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// validRunConfig returns a config that passes run()'s validation, with an
// in-tempdir allowlist DB and hermetic endpoints. The cluster it serves is the
// measured configuration; pass another with measuredConfig to vary the
// operator keys or the workloads.
func validRunConfig(t *testing.T, attestationURL string) config {
	t.Helper()
	return config{
		measured:                   measuredConfig(t, cluster{operatorPEM: operatorKeysPEM(t), workloads: map[string]string{"cds": digestA}}),
		host:                       "127.0.0.1",
		port:                       0,
		logLevel:                   "error",
		attestationApiURL:          attestationURL,
		caCommonName:               "test ca",
		caCertValidity:             24 * time.Hour,
		jwtClockSkew:               30,
		certTTL:                    time.Hour,
		namedCertTTL:               issuer.MaxNamedLeafTTL,
		challengeTTL:               time.Minute,
		requestTimeout:             time.Second,
		maxRequestSize:             65536,
		secretsMaxPaths:            1024,
		secretsMaxPathsPerWorkload: 64,
		secretsMaxValueBytes:       4096,
		sandboxLedgerMax:           10000,
		readinessInterval:          50 * time.Millisecond,
		minCAValidity:              time.Hour,
		allowlistDB:                filepath.Join(t.TempDir(), "allowlist.db"),
		rateLimit:                  1000,
		rateBurst:                  1000,
		rateLimiterMax:             1000,
		rateLimiterEvictInterval:   time.Minute,
		rateLimiterIdleTimeout:     5 * time.Minute,
		armtlsPlatform:             teetypes.FamilySNP,
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestRun_ErrorPaths(t *testing.T) {
	api := newHealthyAttestationApi(t)

	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, cfg *config)
		wantSub string
	}{
		{
			name:    "bad log level",
			mutate:  func(_ *testing.T, cfg *config) { cfg.logLevel = "bogus" },
			wantSub: "--log-level",
		},
		{
			name:    "invalid config",
			mutate:  func(_ *testing.T, cfg *config) { cfg.namedCertTTL = 0 },
			wantSub: "--named-cert-ttl",
		},
		{
			name:    "rate limiter max entries",
			mutate:  func(_ *testing.T, cfg *config) { cfg.rateLimiterMax = 0 },
			wantSub: "rate limiter",
		},
		{
			name: "allowlist db unopenable",
			mutate: func(t *testing.T, cfg *config) {
				cfg.allowlistDB = filepath.Join(t.TempDir(), "no-such-dir", "allowlist.db")
			},
			wantSub: "allowlist database",
		},
		{
			name: "tampered allowlist history fails closed",
			mutate: func(t *testing.T, cfg *config) {
				store, err := allowlist.OpenStore(cfg.allowlistDB)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.StartJournal(); err != nil {
					t.Fatal(err)
				}
				store.Close()
				db, err := sql.Open("sqlite", cfg.allowlistDB)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec("UPDATE journal_object SET body = CAST('{}' AS BLOB)"); err != nil {
					t.Fatal(err)
				}
			},
			wantSub: "allowlist history",
		},
		{
			name:    "invalid cn pattern",
			mutate:  func(_ *testing.T, cfg *config) { cfg.allowedCNPattern = "(" },
			wantSub: "--allowed-cn-pattern",
		},
		{
			name:    "unsupported armtls platform",
			mutate:  func(_ *testing.T, cfg *config) { cfg.armtlsPlatform = "bogus-platform" },
			wantSub: "unsupported TEE platform",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validRunConfig(t, api.URL)
			tc.mutate(t, &cfg)
			err := run(cfg)
			if err == nil {
				t.Fatalf("run() succeeded, want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("run() error = %q, want it to contain %q", err, tc.wantSub)
			}
		})
	}
}

// Full startup from a measured configuration, with SAN validation enabled.
// run() must serve /healthz and exit cleanly on SIGTERM.
func TestRun_ServesAndShutsDownOnSIGTERM(t *testing.T) {
	cfg := armTLSRunConfig(t)
	cfg.allowedCNPattern = `^.*$`
	cfg.sanValidation = true
	client := armTLSClient(nil)

	errCh := make(chan error, 1)
	go func() { errCh <- run(cfg) }()

	base := fmt.Sprintf("https://127.0.0.1:%d", cfg.port)
	deadline := time.Now().Add(15 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("run() exited early: %v", err)
		default:
		}
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				up = true
			}
		}
		if up {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !up {
		t.Fatal("cds never became healthy")
	}

	// The seeded allowlist must be served before shutdown.
	resp, err := client.Get(base + "/allowlist")
	if err != nil {
		t.Fatalf("GET /allowlist: %v", err)
	}
	body := resp.Body
	var listing struct {
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	decodeErr := json.NewDecoder(body).Decode(&listing)
	_ = body.Close()
	if decodeErr != nil {
		t.Fatalf("decode /allowlist: %v", decodeErr)
	}
	if _, ok := listing.Workloads["cds"]; !ok {
		t.Errorf("seeded entry missing from /allowlist: %v", listing.Workloads)
	}

	// Operator keys are pinned, so /operator-keys must serve the bundle.
	resp, err = client.Get(base + "/operator-keys")
	if err != nil {
		t.Fatalf("GET /operator-keys: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /operator-keys = %d, want 200", resp.StatusCode)
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() returned error on shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not shut down after SIGTERM")
	}
}

// startRunServer launches run(cfg) on its armTLS listener, waits for /healthz,
// and registers a cleanup that SIGTERMs the process and requires a clean exit.
// It returns the base URL and the client that reaches it.
func startRunServer(t *testing.T, cfg config) (string, *http.Client) {
	t.Helper()
	base := fmt.Sprintf("https://127.0.0.1:%d", cfg.port)
	client := armTLSClient(nil)
	startRunServerOn(t, cfg, base, client)
	return base, client
}

// startRunServerOn is startRunServer for a listener that client knows how to
// reach: base carries the scheme, and client the TLS configuration.
func startRunServerOn(t *testing.T, cfg config, base string, client *http.Client) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- run(cfg) }()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("cds never became healthy")
		}
		select {
		case err := <-errCh:
			t.Fatalf("run() exited early: %v", err)
		default:
		}
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Cleanup(func() {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("send SIGTERM: %v", err)
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("run() returned error on shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("run() did not shut down after SIGTERM")
		}
	})
}

// TestRun_LogsNodeImagePinning: the configuration's node identities must log
// the pinning-enabled line, not the UNSAFE empty-allowlist warning. A bad CN
// pattern stops startup after the pinning log.
func TestRun_LogsNodeImagePinning(t *testing.T) {
	api := newHealthyAttestationApi(t)
	cfg := validRunConfig(t, api.URL)
	cfg.logLevel = "info"
	cfg.allowedCNPattern = "("

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	runErr := run(cfg)
	os.Stdout = orig
	// run() left slog's default pointed at the pipe; detach it before closing.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	_ = w.Close()
	logged, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured logs: %v", err)
	}

	if runErr == nil || !strings.Contains(runErr.Error(), "--allowed-cn-pattern") {
		t.Fatalf("run() error = %v, want --allowed-cn-pattern failure", runErr)
	}
	if !strings.Contains(string(logged), "node image pinning enabled") {
		t.Fatalf("startup log missing pinning-enabled line:\n%s", logged)
	}
	if strings.Contains(string(logged), "name no launch measurement") {
		t.Fatalf("startup log warned about empty measurements despite pinning:\n%s", logged)
	}
}

// A node-image upgrade pins the image being replaced and the one being rolled
// out at once, and on TDX each carries its own registers. CDS serves such a
// configuration; startRunServer fails the test if run() exits instead.
func TestRun_ServesNodeImagesWithDifferentRegisters(t *testing.T) {
	cfg := armTLSRunConfig(t)
	cfg.measured = measuredConfig(t, cluster{
		operatorPEM: operatorKeysPEM(t),
		workloads:   map[string]string{"cds": digestA},
		nodes:       upgradingNodesDocument,
	})
	startRunServer(t, cfg)
}

// TestRun_AllowlistWriteAcceptsClockSkewedToken: the operator-token verifier
// must apply --jwt-clock-skew as leeway, so a token stamped by a slightly-fast
// operator clock still authorizes the write.
func TestRun_AllowlistWriteAcceptsClockSkewedToken(t *testing.T) {
	operatorKey, keysPEM := operatorKeyPair(t)
	cfg := armTLSRunConfig(t) // jwtClockSkew: 30
	cfg.measured = measuredConfig(t, cluster{operatorPEM: keysPEM, workloads: map[string]string{"cds": digestA}})
	cfg.allowlistPersistent = true // a non-persistent store refuses tokens for --jwt-clock-skew after start
	base, client := startRunServer(t, cfg)

	body := []byte(anySeed(map[string]string{"cds": digestA}))
	sum := sha256.Sum256(body)
	issued := time.Now().Add(10 * time.Second) // inside the 30s leeway
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat": issued.Unix(),
		"exp": issued.Add(30 * time.Second).Unix(),
		"htm": http.MethodPut,
		"htu": "/allowlist",
		"pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}).SignedString(operatorKey)
	if err != nil {
		t.Fatalf("sign operator token: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, base+"/allowlist", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT /allowlist: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /allowlist = %d (%s), want 204", resp.StatusCode, respBody)
	}
}

// A non-persistent store forgets spent tokens at restart, so CDS refuses a
// fresh token until --jwt-clock-skew has passed since start.
func TestRun_NonPersistentStoreRefusesTokensAfterStart(t *testing.T) {
	operatorKey, keysPEM := operatorKeyPair(t)
	cfg := armTLSRunConfig(t) // jwtClockSkew: 30, not persistent
	cfg.measured = measuredConfig(t, cluster{operatorPEM: keysPEM, workloads: map[string]string{"cds": digestA}})
	base, client := startRunServer(t, cfg)

	body := []byte(anySeed(map[string]string{"cds": digestA}))
	sum := sha256.Sum256(body)
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
		"htm": http.MethodPut,
		"htu": "/allowlist",
		"pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}).SignedString(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, base+"/allowlist", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(respBody), operatorauth.ErrTokenBeforeStart.Error()) {
		t.Fatalf("PUT /allowlist = %d (%s), want 401 carrying operatorauth.ErrTokenBeforeStart", resp.StatusCode, respBody)
	}
}

// A whole-document write stores its token as the document's signature, so the
// token must not authorize a second write.
func TestRun_AllowlistWriteTokenSignsOnce(t *testing.T) {
	operatorKey, keysPEM := operatorKeyPair(t)
	cfg := armTLSRunConfig(t)
	cfg.measured = measuredConfig(t, cluster{operatorPEM: keysPEM, workloads: map[string]string{"cds": digestA}})
	cfg.allowlistPersistent = true // a non-persistent store refuses tokens for --jwt-clock-skew after start
	base, client := startRunServer(t, cfg)

	doc, err := pkgallowlist.ParseJSON([]byte(anySeed(map[string]string{"web": digestA})))
	if err != nil {
		t.Fatal(err)
	}
	body, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	hexDigest := hex.EncodeToString(sum[:])
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
		"htm": http.MethodPut,
		"htu": "/allowlist",
		"pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}).SignedString(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	put := func() int {
		req, err := http.NewRequest(http.MethodPut, base+"/allowlist", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get := func(path string) []byte {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, b)
		}
		return b
	}

	if code := put(); code != http.StatusNoContent {
		t.Fatalf("PUT /allowlist = %d, want 204", code)
	}
	if code := put(); code != http.StatusConflict {
		t.Fatalf("PUT /allowlist replaying the token = %d, want 409", code)
	}

	var history struct {
		Entries []allowlist.HistoryEntry `json:"entries"`
	}
	if err := json.Unmarshal(get("/allowlist/history"), &history); err != nil {
		t.Fatal(err)
	}
	if n := len(history.Entries); n != 2 || history.Entries[1].Digest != "sha256:"+hexDigest || !history.Entries[1].Signed {
		t.Fatalf("history = %+v, want the startup document then the signed write", history.Entries)
	}
	if got := get("/allowlist/objects/sha256/" + hexDigest); !bytes.Equal(got, body) {
		t.Fatalf("object = %s, want %s", got, body)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(keysPEM)
	if err != nil {
		t.Fatal(err)
	}
	stored := string(get("/allowlist/objects/sha256/" + hexDigest + "/signature"))
	if err := operatorauth.VerifyStored(keys, stored, http.MethodPut, "/allowlist", body); err != nil {
		t.Fatalf("VerifyStored(served signature) = %v", err)
	}
}

// TestRun_ARMTLSWarmupFailureFailsClosed: with armTLS enabled, a failed serving
// cert warm-up must abort startup instead of serving.
func TestRun_ARMTLSWarmupFailureFailsClosed(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no evidence for you", http.StatusInternalServerError)
	}))
	t.Cleanup(api.Close)
	cfg := validRunConfig(t, api.URL)
	cfg.port = freePort(t)
	cfg.armtlsPlatform = "sev-snp"

	errCh := make(chan error, 1)
	go func() { errCh <- run(cfg) }()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "warm up") {
			t.Fatalf("run() error = %v, want warm-up failure", err)
		}
	case <-time.After(20 * time.Second):
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		<-errCh
		t.Fatal("run() kept serving after armTLS warm-up failure")
	}
}

// armTLSRunConfig returns validRunConfig with the armTLS listener on. A stub
// attestation API provisions both certificates run() warms up, the serving
// certificate and the sandbox-digests client's, with a fake SNP report.
func armTLSRunConfig(t *testing.T) config {
	t.Helper()
	cfg := validRunConfig(t, mockapi.New(t).URL())
	cfg.port = freePort(t)
	cfg.armtlsPlatform = "sev-snp"
	return cfg
}

// armTLSClient returns an HTTPS client that accepts the CDS serving
// certificate only if it carries an armTLS attestation. The attestation
// itself is not verified: the stub's report is unsigned. A cert, if given, is
// presented whenever the server asks for one; crypto/tls would otherwise
// withhold a certificate whose issuer the server does not list as acceptable,
// and the policy under test would never see it.
func armTLSClient(cert *tls.Certificate) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := armtls.ExtractAttestation(cs.PeerCertificates[0])
			return err
		},
	}
	if cert != nil {
		tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// The real armTLS listener, with the client-certificate policy run() sets:
// VerifyClientCertIfGiven against the mesh CA. A client with no certificate
// reads every document the CDS publishes.
func TestRun_ARMTLSServesPublishedDocumentsToCertlessClients(t *testing.T) {
	cfg := armTLSRunConfig(t)
	base := fmt.Sprintf("https://127.0.0.1:%d", cfg.port)
	client := armTLSClient(nil)
	startRunServerOn(t, cfg, base, client)

	for _, tc := range []struct {
		document string
		path     string
		check    func(t *testing.T, body []byte)
	}{
		{"mesh CA certificate", "/ca", func(t *testing.T, body []byte) {
			block, _ := pem.Decode(body)
			if block == nil || block.Type != "CERTIFICATE" {
				t.Fatalf("GET /ca body is not a PEM certificate: %q", body)
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				t.Fatalf("GET /ca certificate: %v", err)
			}
		}},
		{"reference values", "/measurements", func(t *testing.T, body []byte) {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(body, &doc); err != nil || len(doc) == 0 {
				t.Fatalf("GET /measurements body = %q, want a JSON document: %v", body, err)
			}
		}},
		{"operator key set", "/operator-keys", func(t *testing.T, body []byte) {
			if block, _ := pem.Decode(body); block == nil || block.Type != "PUBLIC KEY" {
				t.Fatalf("GET /operator-keys body is not a PEM public key: %q", body)
			}
		}},
		{"allowlist", "/allowlist", func(t *testing.T, body []byte) {
			var listing struct {
				Workloads map[string]json.RawMessage `json:"workloads"`
			}
			if err := json.Unmarshal(body, &listing); err != nil {
				t.Fatalf("decode /allowlist: %v", err)
			}
			if _, ok := listing.Workloads["cds"]; !ok {
				t.Fatalf("seeded entry missing from /allowlist: %v", listing.Workloads)
			}
		}},
	} {
		t.Run(tc.document, func(t *testing.T) {
			resp, err := client.Get(base + tc.path)
			if err != nil {
				t.Fatalf("GET %s over armTLS: %v", tc.path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d (%s), want 200", tc.path, resp.StatusCode, body)
			}
			tc.check(t, body)
		})
	}
}

// pastHalfLife is the renewal trigger: half the certificate's lifetime,
// leaving the rest of it for renewal to keep retrying in.
func TestPastHalfLife(t *testing.T) {
	now := time.Now()
	window := func(start, end time.Duration) *x509.Certificate {
		return &x509.Certificate{
			NotBefore: now.Add(start),
			NotAfter:  now.Add(end),
		}
	}

	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"fresh certificate", window(-time.Minute, time.Hour), false},
		{"just before half its lifetime", window(-29*time.Minute, 31*time.Minute), false},
		{"past half its lifetime", window(-31*time.Minute, 29*time.Minute), true},
		{"expired", window(-2*time.Hour, -time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pastHalfLife(tc.cert, now); got != tc.want {
				t.Errorf("pastHalfLife() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A certificate that is presented is verified against the mesh CA: one the
// CA did not issue fails the handshake, so a handler never sees it. Together
// with the certless reads above this pins ClientAuth to
// VerifyClientCertIfGiven; RequestClientCert would admit this peer and
// RequireAndVerifyClientCert would refuse the certless one.
func TestRun_ARMTLSRefusesClientCertOutsideMeshCA(t *testing.T) {
	cfg := armTLSRunConfig(t)
	base := fmt.Sprintf("https://127.0.0.1:%d", cfg.port)
	startRunServerOn(t, cfg, base, armTLSClient(nil))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stranger"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign client cert: %v", err)
	}
	stranger := armTLSClient(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})

	resp, err := stranger.Get(base + "/ca")
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("GET /ca with a client certificate outside the mesh CA = %d (%s), want a refused handshake", resp.StatusCode, body)
	}
}

// The armTLS listener answers nothing to plain HTTP: a client asking for the
// mesh CA without TLS gets no certificate.
func TestRun_ARMTLSRefusesPlainHTTP(t *testing.T) {
	cfg := armTLSRunConfig(t)
	startRunServerOn(t, cfg, fmt.Sprintf("https://127.0.0.1:%d", cfg.port), armTLSClient(nil))

	// net/http answers a plain request at a TLS listener with a fixed 400,
	// so the refusal is observed as a status, not as a closed connection.
	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get(fmt.Sprintf("http://127.0.0.1:%d/ca", cfg.port))
	if err != nil {
		t.Fatalf("plain-HTTP GET /ca: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain-HTTP GET /ca = %d (%s), want 400", resp.StatusCode, body)
	}
	if block, _ := pem.Decode(body); block != nil {
		t.Fatalf("plain-HTTP GET /ca refused but the body carries a PEM block: %s", body)
	}
}

// Secret writes and explain spend the operator token once, as allowlist writes
// do: the replay is 409 and a freshly minted token still works.
func TestRun_SecretsOperatorTokenSpendsOnce(t *testing.T) {
	cfg := armTLSRunConfig(t)
	operatorKey, keysPEM := operatorKeyPair(t)
	cfg.measured = measuredConfig(t, cluster{operatorPEM: keysPEM, workloads: map[string]string{"cds": digestA}})
	cfg.allowlistPersistent = true // a non-persistent store refuses tokens for --jwt-clock-skew after start
	base := fmt.Sprintf("https://127.0.0.1:%d", cfg.port)
	client := armTLSClient(nil)
	startRunServerOn(t, cfg, base, client)

	der, err := x509.MarshalPKCS8PrivateKey(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	mint := func(method, path string, body []byte) string {
		authz, err := signer.Authorization(method, path, body)
		if err != nil {
			t.Fatal(err)
		}
		return authz
	}
	send := func(method, path string, body []byte, authz string) int {
		req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", authz)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	put, _ := json.Marshal(secrets.PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("v1")), Overwrite: true})
	authz := mint(http.MethodPut, "/secrets/a", put)
	for _, step := range []struct {
		name  string
		authz string
		want  int
	}{
		{"first use", authz, http.StatusCreated},
		{"replay", authz, http.StatusConflict},
		{"fresh token", mint(http.MethodPut, "/secrets/a", put), http.StatusOK},
	} {
		if got := send(http.MethodPut, "/secrets/a", put, step.authz); got != step.want {
			t.Fatalf("PUT /secrets/a, %s = %d, want %d", step.name, got, step.want)
		}
	}

	explain := "/secrets-explain/" + strings.Repeat("a", 64)
	authz = mint(http.MethodGet, explain, nil)
	for _, step := range []struct {
		name  string
		authz string
		want  int
	}{
		{"first use", authz, http.StatusOK},
		{"replay", authz, http.StatusConflict},
		{"fresh token", mint(http.MethodGet, explain, nil), http.StatusOK},
	} {
		if got := send(http.MethodGet, explain, nil, step.authz); got != step.want {
			t.Fatalf("GET %s, %s = %d, want %d", explain, step.name, got, step.want)
		}
	}
}

// A due renewal replaces the published certificate, which is what /ca and
// every issuance then answer with.
func TestRenewMeshCAWhenDueRepublishesTheCertificate(t *testing.T) {
	mesh, err := issuer.NewMeshCA("test ca", 2*time.Millisecond)
	if err != nil {
		t.Fatalf("mesh ca: %v", err)
	}
	first := mesh.Current().CA.Cert

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go renewMeshCAWhenDue(ctx, mesh, time.Millisecond, nil)

	deadline := time.Now().Add(5 * time.Second)
	for mesh.Current().CA.Cert.Equal(first) {
		if time.Now().After(deadline) {
			t.Fatal("renewal did not replace the published certificate")
		}
		time.Sleep(time.Millisecond)
	}
}

// Cancelling the context stops the loop.
func TestRenewMeshCAWhenDueStopsOnContextCancel(t *testing.T) {
	mesh, err := issuer.NewMeshCA("test ca", 2*time.Millisecond)
	if err != nil {
		t.Fatalf("mesh ca: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		renewMeshCAWhenDue(ctx, mesh, time.Millisecond, nil)
		close(stopped)
	}()

	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop outlived its context")

	}
}

func TestCAKeyIDSurvivesARenewal(t *testing.T) {
	mesh, err := issuer.NewMeshCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("mesh ca: %v", err)
	}
	first := mesh.Current().CA.Cert

	renewed, err := mesh.RenewCertificate()
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if bytes.Equal(renewed.CA.Cert.Raw, first.Raw) {
		t.Fatal("renewal published the same certificate, so no field could tell the two apart")
	}
	if got, want := caKeyID(renewed.CA.Cert), caKeyID(first); got != want {
		t.Errorf("key id after renewal = %s, want the retained key's %s", got, want)
	}
}
