package cdsattest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
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

// TestNewCmdHasNoMeshIdentityFlags: no flag points the attestation endpoints
// at a credential other than the member one the router dials with.
func TestNewCmdHasNoMeshIdentityFlags(t *testing.T) {
	flags := NewCmd().Flags()
	for _, name := range []string{"mesh-identity-cert-file", "mesh-identity-key-file", "mesh-identity-ca-file"} {
		if flags.Lookup(name) != nil {
			t.Fatalf("--%s is defined, want no such flag", name)
		}
	}
}

func TestRunErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantSub string
	}{
		{
			name:    "front-door mode is required",
			cfg:     config{},
			wantSub: "--front-door-mode",
		},
		{
			name:    "unknown front-door mode",
			cfg:     config{frontDoorMode: "public"},
			wantSub: "--front-door-mode",
		},
		{
			name:    "missing platform",
			cfg:     config{frontDoorMode: types.FrontDoorModeCDS},
			wantSub: "--platform is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := attestProvider(tc.cfg)
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

func TestCmdRequiresRoutingPort(t *testing.T) {
	cmd := NewCmd()
	cmd.SetArgs([]string{
		"--log-level=error",
		"--cds-url=https://127.0.0.1:9",
		"--attestation-api-url=http://127.0.0.1:9",
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "--routing-port must be between") {
		t.Fatalf("cds-attest without --routing-port = %v, want the --routing-port error", err)
	}
}

func TestRunRefusesBeforeServing(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(*config)
		wantSub string
	}{
		{
			name:    "no front-door mode",
			edit:    func(c *config) { c.frontDoorMode = "" },
			wantSub: "--front-door-mode must be",
		},
		{
			name:    "a front-door mode given twice",
			edit:    func(c *config) { c.frontDoorModeFile = filepath.Join(t.TempDir(), "front-door-mode") },
			wantSub: "mutually exclusive",
		},
		{
			name:    "a plaintext verifier beyond this pod",
			edit:    func(c *config) { c.attestationAPIURL = "http://10.43.0.9:8400" },
			wantSub: "is plaintext at an address this pod named",
		},
		{
			name:    "an unpinned CDS",
			edit:    func(c *config) { c.routing.imagePolicyFile = "" },
			wantSub: cmdsutil.ErrCDSPinUnbound.Error(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := routedRunConfig(t, freePort(t))
			tc.edit(&cfg)
			if err := run(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("run() = %v, want an error containing %q", err, tc.wantSub)
			}
		})
	}
}

// routedRunConfig is a config run accepts, polling a CDS that cannot be
// reached and naming an attestation-api that does not answer.
func routedRunConfig(t *testing.T, attestPort int) config {
	t.Helper()
	return config{
		host:              "127.0.0.1",
		port:              attestPort,
		logLevel:          "error",
		frontDoorMode:     types.FrontDoorModeCDS,
		attestationAPIURL: "http://127.0.0.1:9",
		platform:          "snp",
		readHeaderTimeout: time.Second,
		tunnelIOTimeout:   defaultTunnelIOTimeout,
		establishRate:     defaultEstablishRate,
		establishBurst:    defaultEstablishBurst,
		routing: routingConfig{
			cdsURL:          "https://127.0.0.1:9",
			imagePolicyFile: testutil.CDSPinFile(t),
			launchKeysFile:  filepath.Join(t.TempDir(), "absent"),
			pollInterval:    time.Hour,
			backendTimeout:  time.Hour,
			host:            "127.0.0.1",
			port:            freePort(t),
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

func TestRunRejectsNonPositiveEstablishRate(t *testing.T) {
	for _, zero := range []func(*config){
		func(c *config) { c.establishRate = 0 },
		func(c *config) { c.establishBurst = 0 },
	} {
		cfg := routedRunConfig(t, freePort(t))
		zero(&cfg)
		if err := run(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "--establish-rate and --establish-burst must be positive") {
			t.Fatalf("run() = %v, want the establish-rate error", err)
		}
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

func TestRunReturnsRoutingListenError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cfg := routedRunConfig(t, freePort(t))
	cfg.routing.port = l.Addr().(*net.TCPAddr).Port // already taken
	if err := run(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "routing listener:") {
		t.Fatalf("run() on an occupied routing port = %v, want the routing listener's bind error", err)
	}
}

func TestAttestProviderAsksTheAttestationAPI(t *testing.T) {
	var asked remote.AttestRequest
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&asked); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(remote.AttestResponse{Evidence: json.RawMessage(`{}`)})
	}))
	defer api.Close()
	cfg := config{
		frontDoorMode:     types.FrontDoorModeCDS,
		platform:          "snp",
		generation:        "genoa",
		attestationAPIURL: api.URL,
	}
	provider, err := attestProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, platform, generation, err := provider.Evidence(t.Context(), []byte("report-data"))
	if err != nil {
		t.Fatal(err)
	}
	if string(asked.ReportData) != "report-data" || asked.Platform != teetypes.PlatformSNP {
		t.Fatalf("attestation-api asked %+v, want report_data %q for platform %q", asked, "report-data", teetypes.PlatformSNP)
	}
	if platform != "snp" || generation != "genoa" {
		t.Fatalf("Evidence() platform, generation = %q, %q, want snp, genoa", platform, generation)
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
	port := freePort(t)
	cfg := routedRunConfig(t, port)
	cfg.logLevel = "not-a-level" // exercises the newLogger fallback too
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
