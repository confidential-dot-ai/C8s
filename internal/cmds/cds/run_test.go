package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
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

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
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

func TestCompilePatterns(t *testing.T) {
	t.Run("nil input yields nil slice", func(t *testing.T) {
		got, err := compilePatterns("--x", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil slice, got %v", got)
		}
	})

	t.Run("empties are skipped", func(t *testing.T) {
		got, err := compilePatterns("--x", []string{"", `^a$`, ""})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 compiled pattern (empties skipped), got %d", len(got))
		}
	})

	t.Run("propagates compile error", func(t *testing.T) {
		if _, err := compilePatterns("--x", []string{"["}); err == nil {
			t.Fatal("expected error for invalid regex in list, got nil")
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

// writeOperatorKeyPair generates an operator EC key, writes the public half as
// a PEM bundle, and returns the private key plus the bundle path.
func writeOperatorKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen operator key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal operator key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "operator-keys.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write operator keys: %v", err)
	}
	return key, path
}

// writeOperatorKeysPEM writes a PEM bundle with one EC public key and returns
// its path.
func writeOperatorKeysPEM(t *testing.T) string {
	t.Helper()
	_, path := writeOperatorKeyPair(t)
	return path
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

// validRunConfig returns a config that passes run()'s validation with armTLS
// disabled, an in-tempdir allowlist DB, and hermetic endpoints.
func validRunConfig(t *testing.T, attestationURL string) config {
	t.Helper()
	return config{
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
		armtlsPlatform:             "",
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
			name:    "bad attestation api url",
			mutate:  func(_ *testing.T, cfg *config) { cfg.attestationApiURL = "not a url" },
			wantSub: "--attestation-api-url",
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
			name: "operator keys file missing",
			mutate: func(t *testing.T, cfg *config) {
				cfg.operatorKeys = filepath.Join(t.TempDir(), "missing.pem")
			},
			wantSub: "--operator-keys",
		},
		{
			name: "operator keys file has no EC key",
			mutate: func(t *testing.T, cfg *config) {
				path := filepath.Join(t.TempDir(), "bad.pem")
				if err := os.WriteFile(path, []byte("not pem at all"), 0o600); err != nil {
					t.Fatalf("write bad operator keys: %v", err)
				}
				cfg.operatorKeys = path
			},
			wantSub: "--operator-keys",
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
			name:    "invalid dns san pattern",
			mutate:  func(_ *testing.T, cfg *config) { cfg.dnsSANPatterns = []string{"("} },
			wantSub: "--dns-san-pattern",
		},
		{
			name:    "invalid cn pattern",
			mutate:  func(_ *testing.T, cfg *config) { cfg.allowedCNPattern = "(" },
			wantSub: "--allowed-cn-pattern",
		},
		{
			name: "seed file missing fails closed",
			mutate: func(t *testing.T, cfg *config) {
				cfg.allowlistSeed = filepath.Join(t.TempDir(), "missing-seed.json")
			},
			wantSub: "seed allowlist",
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

// Full plain-HTTP startup: operator keys, measurements, seed, and
// SAN validation enabled. run() must serve /healthz and exit cleanly on SIGTERM.
func TestRun_ServesAndShutsDownOnSIGTERM(t *testing.T) {
	api := newHealthyAttestationApi(t)

	seedPath := filepath.Join(t.TempDir(), "seed.json")
	seedJSON := anySeed(map[string]string{"cds": digestA})
	if err := os.WriteFile(seedPath, []byte(seedJSON), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	cfg := validRunConfig(t, api.URL)
	cfg.port = freePort(t)
	cfg.measurements = []string{strings.Repeat("ab", 48)}
	cfg.dnsSANPatterns = []string{`^[a-z.-]+$`}
	cfg.allowedCNPattern = `^.*$`
	cfg.operatorKeys = writeOperatorKeysPEM(t)
	cfg.allowlistSeed = seedPath
	cfg.sanValidation = true

	errCh := make(chan error, 1)
	go func() { errCh <- run(cfg) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.port)
	deadline := time.Now().Add(15 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("run() exited early: %v", err)
		default:
		}
		resp, err := http.Get(base + "/healthz")
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
	resp, err := http.Get(base + "/allowlist")
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
	resp, err = http.Get(base + "/operator-keys")
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

// startRunServer launches run(cfg) in the background, waits for /healthz, and
// registers a cleanup that SIGTERMs the process and requires a clean exit.
func startRunServer(t *testing.T, cfg config) string {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- run(cfg) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.port)
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
		resp, err := http.Get(base + "/healthz")
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
	return base
}

// TestRun_LogsMeasurementPinning: with --measurements set, startup must log the
// pinning-enabled line, not the UNSAFE empty-allowlist warning. DNS validation
// succeeds first; a bad CN pattern stops startup after the pinning log.
func TestRun_LogsMeasurementPinning(t *testing.T) {
	api := newHealthyAttestationApi(t)
	cfg := validRunConfig(t, api.URL)
	cfg.logLevel = "info"
	cfg.measurements = []string{strings.Repeat("ab", 48)}
	cfg.dnsSANPatterns = []string{`^service[.]example$`}
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
	if !strings.Contains(string(logged), "measurement pinning enabled") {
		t.Fatalf("startup log missing pinning-enabled line:\n%s", logged)
	}
	if strings.Contains(string(logged), "--measurements empty") {
		t.Fatalf("startup log warned about empty measurements despite pinning:\n%s", logged)
	}
}

// TestRun_AllowlistWriteAcceptsClockSkewedToken: the operator-token verifier
// must apply --jwt-clock-skew as leeway, so a token stamped by a slightly-fast
// operator clock still authorizes the write.
func TestRun_AllowlistWriteAcceptsClockSkewedToken(t *testing.T) {
	api := newHealthyAttestationApi(t)
	operatorKey, keysPath := writeOperatorKeyPair(t)
	cfg := validRunConfig(t, api.URL) // jwtClockSkew: 30
	cfg.port = freePort(t)
	cfg.operatorKeys = keysPath
	cfg.allowlistPersistent = true // a non-persistent store refuses tokens for --jwt-clock-skew after start
	base := startRunServer(t, cfg)

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
	resp, err := http.DefaultClient.Do(req)
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
	api := newHealthyAttestationApi(t)
	operatorKey, keysPath := writeOperatorKeyPair(t)
	cfg := validRunConfig(t, api.URL) // jwtClockSkew: 30, not persistent
	cfg.port = freePort(t)
	cfg.operatorKeys = keysPath
	base := startRunServer(t, cfg)

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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(respBody), allowlist.ErrTokenBeforeStart.Error()) {
		t.Fatalf("PUT /allowlist = %d (%s), want 401 carrying ErrTokenBeforeStart", resp.StatusCode, respBody)
	}
}

// A whole-document write stores its token as the document's signature, so the
// token must not authorize a second write.
func TestRun_AllowlistWriteTokenSignsOnce(t *testing.T) {
	api := newHealthyAttestationApi(t)
	operatorKey, keysPath := writeOperatorKeyPair(t)
	cfg := validRunConfig(t, api.URL)
	cfg.port = freePort(t)
	cfg.operatorKeys = keysPath
	cfg.allowlistPersistent = true // a non-persistent store refuses tokens for --jwt-clock-skew after start
	base := startRunServer(t, cfg)

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
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get := func(path string) []byte {
		resp, err := http.Get(base + path)
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
	keys, err := operatorauth.ParsePublicKeysPEM(mustRead(t, keysPath))
	if err != nil {
		t.Fatal(err)
	}
	stored := string(get("/allowlist/objects/sha256/" + hexDigest + "/signature"))
	if err := operatorauth.VerifyStored(keys, stored, http.MethodPut, "/allowlist", body); err != nil {
		t.Fatalf("VerifyStored(served signature) = %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
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

func TestLoadOperatorKeys(t *testing.T) {
	t.Run("valid bundle", func(t *testing.T) {
		path := writeOperatorKeysPEM(t)
		keys, pemBytes, err := loadOperatorKeys(path)
		if err != nil {
			t.Fatalf("loadOperatorKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("keys = %d, want 1", len(keys))
		}
		if len(pemBytes) == 0 {
			t.Error("raw PEM bytes empty")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, _, err := loadOperatorKeys(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("no EC key fails closed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := loadOperatorKeys(path); err == nil {
			t.Fatal("expected error for bundle without EC public key")
		}
	})
}

// measurementDigests renders the /attest allowlist for the callback's pin. It
// must not silently drop an entry: /attest compares the same allowlist as
// strings, so a dropped entry would leave the callback unpinned while /attest
// still enforced it — two derivations of one allowlist disagreeing in the
// direction that weakens the callback.
func TestMeasurementDigests(t *testing.T) {
	valid := map[string]bool{"abcd": true, "ef01": true}
	got, err := measurementDigests(valid)
	if err != nil {
		t.Fatalf("measurementDigests: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d digests, want 2", len(got))
	}

	if _, err := measurementDigests(map[string]bool{"abcd": true, "0xnothex": true}); err == nil {
		t.Fatal("a non-hex measurement was dropped instead of failing startup")
	}

	empty, err := measurementDigests(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty allowlist: got %v, %v", empty, err)
	}
}
