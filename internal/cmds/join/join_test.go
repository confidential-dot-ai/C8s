package join

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// ramTempDir returns a tmpfs-backed temp dir; RunJoin refuses to stage the
// token anywhere else.
func ramTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/dev/shm", "c8s-join-")
	if err != nil {
		t.Skipf("no tmpfs temp dir available: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// joinConfig returns a JoinConfig pointing at server with outputs in a temp
// dir.
func joinConfig(t *testing.T, apiURL, serverAddr string) JoinConfig {
	t.Helper()
	dir := ramTempDir(t)
	return JoinConfig{
		ServerAddr:         serverAddr,
		AttestationAPIURL:  apiURL,
		Platform:           "tdx",
		MeasurementsConfig: policyFile(t, teetypes.PlatformTDX, policyEntry(t, teetypes.PlatformTDX, testOperator)),
		TokenOut:           filepath.Join(dir, "join-token"),
		Timeout:            10 * time.Second,
	}
}

// joinServer starts a TLS httptest server with an attested RA-TLS serving
// cert, the shape join-release presents.
func joinServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ratls.CreateAttestedCert(key, &ratls.Attestation{Family: ratls.TEETypeTDX, Report: []byte(tdxEnvelope)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// serverHostPort strips the scheme off an httptest server URL.
func serverHostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "https://")
}

// TestJoinExchangeE2E uses distinct services and distinct operator keys on the
// two nodes. Each side authorizes the other independently on TDX and SNP.
func TestJoinExchangeE2E(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		for _, scenario := range []string{"authorized", "wrong server key", "wrong agent key", "wrong server image", "wrong agent image", "wrong server TEE", "wrong agent TEE"} {
			t.Run(string(platform)+"/"+scenario, func(t *testing.T) {
				t.Parallel()
				dir := ramTempDir(t)
				serverKey, agentKey := operatorKey(t), operatorKey(t)
				serverVerdict := verifyResp(platform, serverKey)
				agentVerdict := verifyResp(platform, agentKey)
				switch scenario {
				case "wrong server key":
					serverVerdict = verifyResp(platform, agentKey)
				case "wrong agent key":
					agentVerdict = verifyResp(platform, serverKey)
				case "wrong server image":
					serverVerdict.Result.Claims.LaunchDigest = digestB
				case "wrong agent image":
					agentVerdict.Result.Claims.LaunchDigest = digestB
				}
				serverAPI := newFakeAPI(t, staticVerify(agentVerdict))
				agentAPI := newFakeAPI(t, staticVerify(serverVerdict))
				serverAPI.platform, agentAPI.platform = platform, platform
				other := teetypes.PlatformSNP
				if platform == teetypes.PlatformSNP {
					other = teetypes.PlatformTDX
				}
				if scenario == "wrong server TEE" {
					serverAPI.platform = other
				}
				if scenario == "wrong agent TEE" {
					agentAPI.platform = other
				}
				relCfg := releaseConfig(t)
				relCfg.Platform = string(platform)
				relCfg.AttestationAPIURL = serverAPI.URL
				relCfg.MeasurementsConfig = policyFile(t, platform, policyEntry(t, platform, agentKey))
				if err := os.WriteFile(relCfg.TokenPath, []byte(testToken+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(relCfg.TokenPath), "token"), []byte(testCA+"::server:privileged-secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				relCfg.ListenAddr = ln.Addr().String()
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- runRelease(ctx, relCfg, ln) }()
				defer func() {
					cancel()
					ln.Close()
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("join release did not shut down")
					}
				}()
				cfg := JoinConfig{ServerAddr: relCfg.ListenAddr, AttestationAPIURL: agentAPI.URL, Platform: string(platform),
					MeasurementsConfig: policyFile(t, platform, policyEntry(t, platform, serverKey)), TokenOut: filepath.Join(dir, "join-token"),
					Timeout: 2 * time.Second}
				err = RunJoin(context.Background(), cfg)
				if scenario != "authorized" {
					if err == nil {
						t.Fatal("unauthorized peer enrolled")
					}
					assertAbsent(t, cfg.TokenOut)
					return
				}
				if err != nil {
					t.Fatalf("RunJoin: %v", err)
				}
				token, err := os.ReadFile(cfg.TokenOut)
				if err != nil {
					t.Fatal(err)
				}
				if string(token) != testToken+"\n" {
					t.Fatal("wrong staged token")
				}
				assertMode(t, cfg.TokenOut, 0600)
				if serverAPI.verifyCalls.Load() != 1 || agentAPI.verifyCalls.Load() != 1 {
					t.Fatalf("mutual verification: server %d, agent %d", serverAPI.verifyCalls.Load(), agentAPI.verifyCalls.Load())
				}
				// join must never write an rke2 drop-in: launch-config
				// staging is that file's only owner.
				assertAbsent(t, filepath.Join(dir, "50-join.yaml"))
			})
		}
	}
}

// TestJoinRefusesMismatchedServer: the client's verifier reports the server's
// operator key differs from the designated server; the handshake must fail and nothing may be
// staged.
func TestJoinRefusesMismatchedServer(t *testing.T) {
	api := newFakeAPI(t, func(call int, _ remote.VerifyRequest) remote.VerifyResponse {
		return verifyResp(teetypes.PlatformTDX, operatorKey(t))
	})
	srv := joinServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request reached the server despite a failed verification")
	}))

	cfg := joinConfig(t, api.URL, serverHostPort(t, srv))
	err := RunJoin(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected RunJoin to fail")
	}
	if !errors.Is(err, ratls.ErrPolicyViolation) && !strings.Contains(err.Error(), ratls.ErrPolicyViolation.Error()) {
		t.Fatalf("err = %v, want policy mismatch", err)
	}
	assertAbsent(t, cfg.TokenOut)
}

// TestJoinServerErrors: an attested, authorized server that refuses or
// misbehaves must surface an error and stage nothing.
func TestJoinServerErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"denied", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "join denied", http.StatusForbidden)
		}},
		{"not ready", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "join token not ready", http.StatusServiceUnavailable)
		}},
		{"empty token", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":""}`))
		}},
		{"garbage body", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
			srv := joinServer(t, tc.handler)
			cfg := joinConfig(t, api.URL, serverHostPort(t, srv))
			if err := RunJoin(context.Background(), cfg); err == nil {
				t.Fatal("expected RunJoin to fail")
			}
			assertAbsent(t, cfg.TokenOut)
		})
	}
}

func TestRunJoinConfigErrors(t *testing.T) {
	api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
	tests := []struct {
		name   string
		mutate func(*JoinConfig)
	}{
		{"platform required", func(c *JoinConfig) { c.Platform = "" }},
		{"server must be host:port", func(c *JoinConfig) { c.ServerAddr = "10.0.0.5" }},
		{"attestation-api down", func(c *JoinConfig) {
			c.AttestationAPIURL = "http://127.0.0.1:1"
			c.Timeout = time.Second
		}},
		{"timeout must be positive", func(c *JoinConfig) { c.Timeout = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := joinConfig(t, api.URL, "127.0.0.1:1")
			tc.mutate(&cfg)
			if err := RunJoin(context.Background(), cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestWriteStaged(t *testing.T) {
	dir := t.TempDir()
	cfg := JoinConfig{TokenOut: filepath.Join(dir, "run", "join-token")}
	// Pre-create the output world-readable: os.WriteFile's perm applies only
	// on create, so a stale file would keep leaking the token.
	if err := os.MkdirAll(filepath.Dir(cfg.TokenOut), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.TokenOut, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Dir(cfg.TokenOut))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeStaged(cfg, root, "tok"); err != nil {
		t.Fatal(err)
	}
	assertMode(t, cfg.TokenOut, 0o600)
	if token, err := os.ReadFile(cfg.TokenOut); err != nil {
		t.Fatal(err)
	} else if string(token) != "tok\n" {
		t.Errorf("token = %q, want the fresh value", token)
	}
}

// TestPrepareTokenDir: the "must be tmpfs" invariant is enforced, not merely
// documented.
func TestPrepareTokenDir(t *testing.T) {
	t.Run("tmpfs accepted", func(t *testing.T) {
		root, err := prepareTokenDir(filepath.Join(ramTempDir(t), "confos", "join-token"))
		if err != nil {
			t.Fatal(err)
		}
		root.Close()
	})

	t.Run("persistent storage refused", func(t *testing.T) {
		dir := t.TempDir()
		if fileutil.RequireRAMBacked(dir) == nil {
			t.Skipf("%s is RAM-backed; no on-disk path to reject", dir)
		}
		if root, err := prepareTokenDir(filepath.Join(dir, "join-token")); err == nil {
			root.Close()
			t.Fatal("expected a token-out on persistent storage to be refused")
		}
	})
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != want {
		t.Errorf("%s mode = %#o, want %#o", path, fi.Mode().Perm(), want)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists (err=%v), want absent", path, err)
	}
}

func TestFetchTokenStrictResponse(t *testing.T) {
	valid := `{"token":"` + testToken + `"}`
	for _, tc := range []struct {
		name, body string
		accept     bool
	}{
		{"valid", valid, true}, {"whitespace", valid + " \n", true},
		{"trailing document", valid + `{}`, false}, {"trailing junk", valid + `x`, false},
		{"duplicate token", `{"token":"` + testToken + `","token":"` + testToken + `"}`, false},
		{"unknown field", `{"token":"` + testToken + `","extra":true}`, false},
		{"wrong field case", `{"Token":"` + testToken + `"}`, false},
		{"null", `null`, false}, {"null token", `{"token":null}`, false},
		{"privileged token", `{"token":"` + testCA + `::server:secret"}`, false},
		{"invalid hash", `{"token":"K10cafe::node:secret"}`, false},
		{"response too large", valid + strings.Repeat(" ", maxTokenRespBytes), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
			defer srv.Close()
			token, err := fetchToken(context.Background(), JoinConfig{ServerAddr: serverHostPort(t, srv), Timeout: time.Second}, &tls.Config{InsecureSkipVerify: true})
			if (err == nil) != tc.accept {
				t.Fatalf("err=%v accept=%v", err, tc.accept)
			}
			if tc.accept && token != testToken {
				t.Fatal("wrong returned token")
			}
		})
	}
}

func TestTokenStagingSurvivesDirectoryReplacement(t *testing.T) {
	ramDir := ramTempDir(t)
	path := filepath.Join(ramDir, "checked")
	cfg := JoinConfig{TokenOut: filepath.Join(path, "join-token")}
	root, err := prepareTokenDir(cfg.TokenOut)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	moved := filepath.Join(ramDir, "original")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	disk := t.TempDir()
	if err := os.Symlink(disk, path); err != nil {
		t.Fatal(err)
	}
	if err := writeStaged(cfg, root, testToken); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, filepath.Join(disk, "join-token"))
	token, err := os.ReadFile(filepath.Join(moved, "join-token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(token) != testToken+"\n" {
		t.Fatal("token not written to checked root")
	}
}

func TestJoinRejectsMissingPolicyBeforeNetwork(t *testing.T) {
	api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, testOperator)))
	cfg := JoinConfig{Platform: "tdx", ServerAddr: "127.0.0.1:1", AttestationAPIURL: api.URL, Timeout: time.Second, TokenOut: filepath.Join(t.TempDir(), "join-token")}
	if err := RunJoin(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "measurements-config") {
		t.Fatalf("err=%v", err)
	}
	if api.verifyCalls.Load() != 0 {
		t.Fatal("missing policy reached network")
	}
	assertAbsent(t, cfg.TokenOut)
}

func TestPinnedServerCertAcceptsOnlyTheVerifiedLeaf(t *testing.T) {
	verify := pinnedServerCert([]byte("verified leaf"))
	if err := verify([][]byte{[]byte("verified leaf")}, nil); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][][]byte{nil, {[]byte("rotated leaf")}} {
		if err := verify(raw, nil); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
