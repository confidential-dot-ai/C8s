package cdsattest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type config struct {
	host                 string
	port                 int
	logLevel             string
	frontDoorMode        types.FrontDoorMode
	servingCertFile      string
	meshIdentityCertFile string
	meshIdentityKeyFile  string
	meshIdentityCAFile   string
	expectedWorkload     string
	measuredPolicies     string
	evidenceFixture      string
	attestationAPIURL    string
	platform             string
	generation           string
	sessionTTL           time.Duration
	sessionMaxAge        time.Duration
	readHeaderTimeout    time.Duration
	tunnelIOTimeout      time.Duration

	// Launch-driven inputs (node image): each file overrides its flag.
	frontDoorModeFile   string
	acmeServingCertFile string

	// attestOff unregisters attest-pq, attest-lb and the tunnel
	// (--attest-endpoints=false). Negative so a zero config keeps them.
	attestOff bool
	routing   routingConfig
}

// NewCmd returns the `cds-attest` subcommand: a sidecar that runs inside the
// router pod, routes application requests by the operator-signed route
// manifest, and serves the *dynamic* client-facing attestation +
// over-encryption endpoints (the c8s-verify protocol). The router nginx
// front-end terminates public TLS, serves the static CDS/mesh-CA certs, and
// reverse-proxies /.well-known/c8s/ and every application request to this
// sidecar on loopback.
func NewCmd() *cobra.Command {
	var cfg config
	attestEndpoints := true
	cmd := &cobra.Command{
		Use:   "cds-attest",
		Short: "Run the router routing, attestation and over-encryption sidecar",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.attestOff = !attestEndpoints
			cfg.routing.operatorKeysFileSet = cmd.Flags().Changed("operator-keys-file")
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return run(ctx, cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.host, "host", "127.0.0.1", "listen host (loopback: nginx proxies to it)")
	f.IntVarP(&cfg.port, "port", "p", 8800, "listen port")
	f.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	f.StringVar((*string)(&cfg.frontDoorMode), "front-door-mode", "", "REQUIRED: which credential terminates public TLS in front of this sidecar: cds (TEE-held mesh-issued serving key; attest-lb served), acme (TEE-held in-guest ACME serving key; attest-lb served), or webpki (host-visible Secret; attest-lb refused with external_tls)")
	f.StringVar(&cfg.servingCertFile, "serving-cert-file", "", "path to the LB serving-leaf PEM (the cert nginx presents). In cds front-door mode, GET /.well-known/c8s/attest-lb binds report_data to this exact leaf DER. Re-read per request to follow get-cert rotation.")
	f.StringVar(&cfg.meshIdentityCertFile, "mesh-identity-cert-file", "", "TEE-held mesh leaf PEM whose possession both attestation endpoints prove (re-read per request)")
	f.StringVar(&cfg.meshIdentityKeyFile, "mesh-identity-key-file", "", "TEE-held mesh leaf private key matching --mesh-identity-cert-file (re-read per request)")
	f.StringVar(&cfg.meshIdentityCAFile, "mesh-identity-ca-file", "", "mesh CA bundle that issued the identity leaf (re-read per request)")
	f.StringVar(&cfg.expectedWorkload, "expected-workload", "", "gate /readyz on the mesh identity leaf carrying a matched-workload stamp with this exact name; empty keeps /readyz unconditionally 200")
	f.StringVar(&cfg.measuredPolicies, "measured-policies-file", "", "the node's journal of allowlist policies extended into TDX RTMR[3]; attest-pq and attest-lb bundles carry it as measured_policies. Empty omits the list")
	f.StringVar(&cfg.evidenceFixture, "evidence-fixture", "", "DEV ONLY: serve recorded TEE evidence from this file instead of the attestation-api")
	f.StringVar(&cfg.attestationAPIURL, "attestation-api-url", "", "attestation-api URL (production evidence source)"+cmdsutil.NodeAddressHelp)
	f.StringVar(&cfg.platform, "platform", "", "REQUIRED: TEE platform: snp|az-snp|az-tdx|tdx")
	f.StringVar(&cfg.generation, "generation", "genoa", "AMD processor generation for the browser's bare-SNP verifier (platform snp only, ignored otherwise): milan|genoa|turin")
	f.DurationVar(&cfg.sessionTTL, "session-ttl", 5*time.Minute, "established-session idle TTL")
	f.DurationVar(&cfg.sessionMaxAge, "session-max-age", defaultSessionMaxAge, "absolute session lifetime: a session's keys retire this long after establishment, however busy it is")
	f.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", 5*time.Second, "HTTP read-header timeout")
	f.DurationVar(&cfg.tunnelIOTimeout, "tunnel-io-timeout", defaultTunnelIOTimeout, "how long a tunnel upload, or its sealed response download, may make no progress")
	f.StringVar(&cfg.frontDoorModeFile, "front-door-mode-file", "", "file holding the front-door mode, read at start instead of --front-door-mode")
	f.StringVar(&cfg.acmeServingCertFile, "acme-serving-cert-file", "", "serving-leaf PEM nginx presents in acme front-door mode; used instead of --serving-cert-file when --front-door-mode-file reads acme")
	f.BoolVar(&attestEndpoints, "attest-endpoints", true, "serve attest-pq, attest-lb and the tunnel; false serves only the routing listener and probes")
	bindRoutingFlags(f, &cfg.routing)
	return cmd
}

// loadFiles applies the launch-driven file inputs over their flags.
func loadFiles(cfg *config) error {
	if cfg.frontDoorModeFile != "" {
		if cfg.frontDoorMode != "" {
			return fmt.Errorf("--front-door-mode and --front-door-mode-file are mutually exclusive")
		}
		data, err := os.ReadFile(cfg.frontDoorModeFile)
		if err != nil {
			return fmt.Errorf("--front-door-mode-file: %w", err)
		}
		cfg.frontDoorMode = types.FrontDoorMode(strings.TrimSpace(string(data)))
		if cfg.frontDoorMode == types.FrontDoorModeACME && cfg.acmeServingCertFile != "" {
			cfg.servingCertFile = cfg.acmeServingCertFile
		}
	}
	return nil
}

// run serves until ctx is cancelled.
func run(ctx context.Context, cfg config) error {
	logger := newLogger(cfg.logLevel)
	rawAttestationURL := cfg.attestationAPIURL
	attestationURL, err := cmdsutil.ExpandHostIP(rawAttestationURL)
	if err != nil {
		return err
	}
	cfg.attestationAPIURL = attestationURL
	if err := loadFiles(&cfg); err != nil {
		return err
	}
	if cfg.tunnelIOTimeout <= 0 {
		return errors.New("--tunnel-io-timeout must be positive")
	}
	if err := checkRoutingFlags(cfg); err != nil {
		return err
	}

	var provider EvidenceProvider
	if !cfg.attestOff {
		p, err := attestProvider(cfg, logger)
		if err != nil {
			return err
		}
		provider = p
	}

	watchCtx := cmdsutil.WatchNodeIP(ctx, rawAttestationURL, attestationURL)
	ctx, stop := context.WithCancel(watchCtx)
	defer stop()

	engine, err := newRoutingEngine(cfg, logger)
	if err != nil {
		return err
	}

	srvCfg := Config{
		Logger:                 logger,
		Evidence:               provider,
		FrontDoorMode:          cfg.frontDoorMode,
		ServingCertFile:        cfg.servingCertFile,
		MeshIdentityCertFile:   cfg.meshIdentityCertFile,
		MeshIdentityKeyFile:    cfg.meshIdentityKeyFile,
		MeshIdentityCAFile:     cfg.meshIdentityCAFile,
		ExpectedWorkload:       cfg.expectedWorkload,
		MeasuredPoliciesFile:   cfg.measuredPolicies,
		Routes:                 engine.proxy,
		PublishRoutes:          cfg.routing.publish,
		SessionTTL:             cfg.sessionTTL,
		SessionMaxAge:          cfg.sessionMaxAge,
		TunnelIOTimeout:        cfg.tunnelIOTimeout,
		DisableAttestEndpoints: cfg.attestOff,
	}
	srv := NewServer(srvCfg)

	addr := cfg.host + ":" + strconv.Itoa(cfg.port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: cfg.readHeaderTimeout,
	}

	errc := make(chan error, 2)
	if err := engine.start(ctx, cfg.readHeaderTimeout, errc); err != nil {
		return err
	}
	logger.Info("LB browser-facing endpoints listening", "addr", addr, "attest_endpoints", !cfg.attestOff)
	go func() { errc <- srv.Serve(ctx, httpSrv) }()
	err = <-errc
	stop()
	return cmdsutil.NodeIPChanged(watchCtx, err)
}

// attestProvider checks the flags the attestation endpoints need and returns
// their evidence source.
func attestProvider(cfg config, logger *slog.Logger) (EvidenceProvider, error) {
	// No default: serving attest-lb is a trust decision about where the
	// serving key lives, so the deployer must state it.
	switch cfg.frontDoorMode {
	case types.FrontDoorModeCDS, types.FrontDoorModeWebPKI, types.FrontDoorModeACME:
	default:
		return nil, fmt.Errorf("--front-door-mode must be %q, %q, or %q, got %q", types.FrontDoorModeCDS, types.FrontDoorModeWebPKI, types.FrontDoorModeACME, cfg.frontDoorMode)
	}
	// Same rule as front-door-mode: the advertised TEE is a trust statement,
	// so the deployer must state it.
	if cfg.platform == "" {
		return nil, fmt.Errorf("--platform is required: snp, az-snp, az-tdx, or tdx")
	}
	switch {
	case cfg.evidenceFixture != "":
		fp, err := LoadFixtureEvidence(cfg.evidenceFixture, cfg.platform, cfg.generation)
		if err != nil {
			return nil, err
		}
		logger.Warn("serving recorded evidence fixture (DEV ONLY): report_data is not bound to live session keys",
			"file", cfg.evidenceFixture)
		return fp, nil
	case cfg.attestationAPIURL != "":
		return LiveEvidenceProvider{
			Client:     armtls.NewAttestationClient(cfg.attestationAPIURL),
			Platform:   teetypes.NormalizePlatform(cfg.platform),
			Generation: cfg.generation,
		}, nil
	default:
		return nil, fmt.Errorf("one of --attestation-api-url or --evidence-fixture is required")
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		slog.Error("unrecognized log level, defaulting to Info", "requested_level", level, "error", err)
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
