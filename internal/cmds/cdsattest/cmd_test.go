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
		{
			// acme passes the mode gate: the failure is the later upstream check.
			name:    "invalid upstream URL",
			cfg:     config{frontDoorMode: types.FrontDoorModeACME, platform: "snp", evidenceFixture: fixture, upstream: "ftp://backend"},
			wantSub: "upstream must be an http:// or https:// URL",
		},
		{
			// The live-evidence branch must be selected on --attestation-api-url
			// alone; the bad upstream proves run() got past provider selection.
			name:    "invalid upstream URL with live evidence source",
			cfg:     config{frontDoorMode: types.FrontDoorModeWebPKI, platform: "snp", attestationAPIURL: "http://127.0.0.1:9", upstream: "ftp://backend"},
			wantSub: "upstream must be an http:// or https:// URL",
		},
		{
			name:    "non-positive tunnel io timeout",
			cfg:     config{tunnelIOTimeout: -time.Second},
			wantSub: "--tunnel-io-timeout must be positive",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if cfg.tunnelIOTimeout == 0 {
				cfg.tunnelIOTimeout = defaultTunnelIOTimeout
			}
			err := run(t.Context(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("run() error = %v, want substring %q", err, tc.wantSub)
			}
		})
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
	cfg := config{
		host:              "127.0.0.1",
		port:              l.Addr().(*net.TCPAddr).Port, // already taken
		attestationAPIURL: "http://127.0.0.1:9",
		tunnelIOTimeout:   defaultTunnelIOTimeout,
	}
	if err := run(t.Context(), cfg); err == nil {
		t.Fatal("run() on an occupied port returned nil, want bind error")
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
	cfg := config{
		host:              "127.0.0.1",
		port:              port,
		logLevel:          "not-a-level", // exercises the newLogger fallback too
		frontDoorMode:     types.FrontDoorModeCDS,
		evidenceFixture:   fixture,
		platform:          "snp",
		generation:        "genoa",
		sessionTTL:        time.Minute,
		readHeaderTimeout: time.Second,
		tunnelIOTimeout:   defaultTunnelIOTimeout,
		upstream:          "http://127.0.0.1:9", // valid URL; never dialed in this test
	}

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
