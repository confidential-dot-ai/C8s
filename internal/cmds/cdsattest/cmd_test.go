package cdsattest

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestNewCmdDurationDefaults pins the shipped duration-flag defaults.
func TestNewCmdDurationDefaults(t *testing.T) {
	flags := NewCmd().Flags()
	for _, tc := range []struct {
		flag string
		want string
	}{
		{"session-ttl", "5m0s"},
		{"session-max-age", "5h0m0s"},
		{"read-header-timeout", "5s"},
	} {
		f := flags.Lookup(tc.flag)
		if f == nil {
			t.Fatalf("missing --%s flag", tc.flag)
		}
		if f.DefValue != tc.want {
			t.Fatalf("default --%s = %q, want %q", tc.flag, f.DefValue, tc.want)
		}
	}
}

func writeFixtureFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(path, []byte(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunErrors(t *testing.T) {
	fixture := writeFixtureFile(t)
	tests := []struct {
		name    string
		cfg     config
		wantSub string
	}{
		{
			name:    "front-door mode is required",
			cfg:     config{evidenceFixture: fixture},
			wantSub: "--front-door-mode",
		},
		{
			name:    "unknown front-door mode",
			cfg:     config{frontDoorMode: "public", evidenceFixture: fixture},
			wantSub: "--front-door-mode",
		},
		{
			name:    "missing platform",
			cfg:     config{frontDoorMode: types.FrontDoorModeCDS, evidenceFixture: fixture},
			wantSub: "--platform is required",
		},
		{
			name:    "no evidence source",
			cfg:     config{frontDoorMode: types.FrontDoorModeCDS, platform: "snp"},
			wantSub: "--attestation-api-url or --evidence-fixture",
		},
		{
			name:    "unreadable evidence fixture",
			cfg:     config{frontDoorMode: types.FrontDoorModeCDS, platform: "snp", evidenceFixture: filepath.Join(t.TempDir(), "missing.json")},
			wantSub: "read evidence fixture",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := attestProvider(tc.cfg, slog.New(slog.DiscardHandler))
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("attestProvider() error = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

// TestRunRequiresCDSURL: without a route manifest source nothing could be
// routed, so run refuses before serving anything.
func TestRunRequiresCDSURL(t *testing.T) {
	cfg := routedRunConfig(t, freePort(t))
	cfg.routing.cdsURL = ""
	if err := run(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "--cds-url is required") {
		t.Fatalf("run() without --cds-url = %v, want the --cds-url error", err)
	}
}

// testCDSMeasurement is the launch measurement these tests pin the polled CDS
// to, since armTLS refuses an unpinned endpoint.
const testCDSMeasurement = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

// routedRunConfig is a config run accepts with the attestation endpoints off,
// polling a CDS that cannot be reached.
func routedRunConfig(t *testing.T, port int) config {
	t.Helper()
	identity := writeTestMeshIdentity(t)
	return config{
		host:                 "127.0.0.1",
		port:                 port,
		logLevel:             "error",
		meshIdentityCertFile: identity.certFile,
		meshIdentityKeyFile:  identity.keyFile,
		meshIdentityCAFile:   identity.caFile,
		attestationAPIURL:    "http://127.0.0.1:9",
		readHeaderTimeout:    time.Second,
		tunnelIOTimeout:      defaultTunnelIOTimeout,
		attestOff:            true,
		routing: routingConfig{
			cdsURL:          "https://127.0.0.1:9",
			cdsMeasurements: []string{testCDSMeasurement},
			launchKeysFile:  filepath.Join(t.TempDir(), "absent"),
			pollInterval:    time.Hour,
			backendTimeout:  time.Hour,
			host:            "127.0.0.1",
			reservedPaths:   defaultReservedPaths,
			tunnelBudget:    quantityFlag{bytes: oneRequestBudget, set: true},
		},
	}
}

func TestRunRejectsNonPositiveTunnelIOTimeout(t *testing.T) {
	cfg := routedRunConfig(t, freePort(t))
	cfg.tunnelIOTimeout = 0
	if err := run(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "--tunnel-io-timeout must be positive") {
		t.Fatalf("run() with --tunnel-io-timeout=0 = %v, want the tunnel-io-timeout error", err)
	}
}

// TestRunReturnsListenError: a failed bind must surface as a run() error, not a
// silent nil exit.
func TestRunReturnsListenError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cfg := routedRunConfig(t, l.Addr().(*net.TCPAddr).Port) // already taken
	cfg.routing.port = freePort(t)
	if err := run(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("run() on an occupied port = %v, want the bind error", err)
	}
}

func TestNewLoggerLevels(t *testing.T) {
	ctx := context.Background()
	if !newLogger("debug").Enabled(ctx, slog.LevelDebug) {
		t.Fatal("newLogger(debug) does not enable debug logging")
	}
	if newLogger("info").Enabled(ctx, slog.LevelDebug) {
		t.Fatal("newLogger(info) unexpectedly enables debug logging")
	}
	if !newLogger("bogus").Enabled(ctx, slog.LevelInfo) {
		t.Fatal("newLogger(bogus) must fall back to info")
	}
}

// freePort grabs an ephemeral port that is free at the time of the call.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestRunServesUntilSignalled(t *testing.T) {
	fixture := writeFixtureFile(t)

	port := freePort(t)
	cfg := routedRunConfig(t, port)
	cfg.attestOff = false
	cfg.logLevel = "not-a-level" // exercises the newLogger fallback too
	cfg.frontDoorMode = types.FrontDoorModeCDS
	cfg.evidenceFixture = fixture
	cfg.platform = "snp"
	cfg.generation = "genoa"
	cfg.sessionTTL = time.Minute

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	var resp *http.Response
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get(base + "/healthz")
		if err == nil {
			break
		}
		select {
		case runErr := <-done:
			t.Fatalf("run exited early: %v", runErr)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatalf("server never came up: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", resp.StatusCode)
	}

	// The standalone cds-cert.pem discovery endpoint is gone: the bundle embeds
	// the exact chain committed by report_data.
	certResp, err := http.Get(base + "/.well-known/c8s/cds-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	certResp.Body.Close()
	if certResp.StatusCode != http.StatusNotFound {
		t.Fatalf("cds-cert.pem status = %d, want 404", certResp.StatusCode)
	}

	cancel()
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("run returned error after cancel: %v", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down after cancel")
	}
}
