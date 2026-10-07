package cdsattest

import (
	"context"
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
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
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
	evidenceFixture      string
	attestationAPIURL    string
	platform             string
	generation           string
	sessionTTL           time.Duration
	sessionMaxAge        time.Duration
	readHeaderTimeout    time.Duration

	// over-encryption backend
	upstream           string
	upstreamCAFile     string
	upstreamCertFile   string
	upstreamKeyFile    string
	upstreamServerName string

	// Launch-driven inputs (node image): each file overrides its flag.
	frontDoorModeFile   string
	upstreamFile        string
	acmeServingCertFile string
}

// NewCmd returns the `cds-attest` subcommand: a sidecar that runs inside the
// router pod and serves the *dynamic* client-facing attestation +
// over-encryption endpoints (the c8s-verify protocol). The router nginx
// front-end terminates public TLS, serves the static CDS/mesh-CA certs, and
// reverse-proxies /.well-known/c8s/attest-pq, /attest-lb, and the
// over-encrypted application paths to this sidecar on loopback.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "cds-attest",
		Short: "Run the router attestation + over-encryption sidecar (attest-pq / attest-lb)",
		RunE:  func(_ *cobra.Command, _ []string) error { return run(cfg) },
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
	f.StringVar(&cfg.evidenceFixture, "evidence-fixture", "", "DEV ONLY: serve recorded TEE evidence from this file instead of the attestation-api")
	f.StringVar(&cfg.attestationAPIURL, "attestation-api-url", "", "attestation-api URL (production evidence source)")
	f.StringVar(&cfg.platform, "platform", "", "REQUIRED: TEE platform: snp|az-snp|az-tdx|tdx")
	f.StringVar(&cfg.generation, "generation", "genoa", "AMD processor generation for the browser's bare-SNP verifier (platform snp only, ignored otherwise): milan|genoa|turin")
	f.DurationVar(&cfg.sessionTTL, "session-ttl", 5*time.Minute, "established-session idle TTL")
	f.DurationVar(&cfg.sessionMaxAge, "session-max-age", defaultSessionMaxAge, "absolute session lifetime: a session's keys retire this long after establishment, however busy it is")
	f.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", 5*time.Second, "HTTP read-header timeout")
	f.StringVar(&cfg.upstream, "upstream", "", "backend base URL to forward decrypted traffic to (http:// rides the armTLS mesh; https:// does mTLS). Empty uses an echo backend (demo).")
	f.StringVar(&cfg.upstreamCAFile, "upstream-ca", "", "PEM CA bundle to verify an https upstream (the mesh CA)")
	f.StringVar(&cfg.upstreamCertFile, "upstream-cert", "", "client cert presented to an https upstream (the CDS-issued LB cert)")
	f.StringVar(&cfg.upstreamKeyFile, "upstream-key", "", "client key for --upstream-cert")
	f.StringVar(&cfg.upstreamServerName, "upstream-server-name", "", "SNI/verification name for an https upstream")
	f.StringVar(&cfg.frontDoorModeFile, "front-door-mode-file", "", "file holding the front-door mode, read at start instead of --front-door-mode")
	f.StringVar(&cfg.upstreamFile, "upstream-file", "", "file holding a mesh-wrapped http upstream host:port, read at start instead of --upstream; an empty file uses the echo backend")
	f.StringVar(&cfg.acmeServingCertFile, "acme-serving-cert-file", "", "serving-leaf PEM nginx presents in acme front-door mode; used instead of --serving-cert-file when --front-door-mode-file reads acme")
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
	if cfg.upstreamFile != "" {
		if cfg.upstream != "" {
			return fmt.Errorf("--upstream and --upstream-file are mutually exclusive")
		}
		data, err := os.ReadFile(cfg.upstreamFile)
		if err != nil {
			return fmt.Errorf("--upstream-file: %w", err)
		}
		if address := strings.TrimSpace(string(data)); address != "" {
			// Plain http is safe only for a mesh-wrapped Service.
			if err := launchconfig.ValidateRouterUpstream(address); err != nil {
				return fmt.Errorf("--upstream-file: %w", err)
			}
			cfg.upstream = "http://" + address
		}
	}
	return nil
}

func run(cfg config) error {
	logger := newLogger(cfg.logLevel)
	if err := loadFiles(&cfg); err != nil {
		return err
	}

	// No default: serving attest-lb is a trust decision about where the
	// serving key lives, so the deployer must state it.
	switch cfg.frontDoorMode {
	case types.FrontDoorModeCDS, types.FrontDoorModeWebPKI, types.FrontDoorModeACME:
	default:
		return fmt.Errorf("--front-door-mode must be %q, %q, or %q, got %q", types.FrontDoorModeCDS, types.FrontDoorModeWebPKI, types.FrontDoorModeACME, cfg.frontDoorMode)
	}
	// Same rule as front-door-mode: the advertised TEE is a trust statement,
	// so the deployer must state it.
	if cfg.platform == "" {
		return fmt.Errorf("--platform is required: snp, az-snp, az-tdx, or tdx")
	}

	var provider EvidenceProvider
	switch {
	case cfg.evidenceFixture != "":
		fp, err := LoadFixtureEvidence(cfg.evidenceFixture, cfg.platform, cfg.generation)
		if err != nil {
			return err
		}
		provider = fp
		logger.Warn("serving recorded evidence fixture (DEV ONLY): report_data is not bound to live session keys",
			"file", cfg.evidenceFixture)
	case cfg.attestationAPIURL != "":
		provider = LiveEvidenceProvider{
			Client:     remote.NewClient(cfg.attestationAPIURL),
			Platform:   teetypes.NormalizePlatform(cfg.platform),
			Generation: cfg.generation,
		}
	default:
		return fmt.Errorf("one of --attestation-api-url or --evidence-fixture is required")
	}

	var backend Backend
	if cfg.upstream != "" {
		hb, err := NewHTTPBackend(cfg.upstream, HTTPBackendOptions{
			TrustedCAFile:  cfg.upstreamCAFile,
			ClientCertFile: cfg.upstreamCertFile,
			ClientKeyFile:  cfg.upstreamKeyFile,
			ServerName:     cfg.upstreamServerName,
		})
		if err != nil {
			return err
		}
		backend = hb
		logger.Info("forwarding decrypted traffic to upstream", "upstream", cfg.upstream)
	} else {
		backend = EchoBackend{}
		logger.Warn("no --upstream set: using echo backend (demo only)")
	}

	srv := NewServer(Config{
		Logger:               logger,
		Evidence:             provider,
		FrontDoorMode:        cfg.frontDoorMode,
		ServingCertFile:      cfg.servingCertFile,
		MeshIdentityCertFile: cfg.meshIdentityCertFile,
		MeshIdentityKeyFile:  cfg.meshIdentityKeyFile,
		MeshIdentityCAFile:   cfg.meshIdentityCAFile,
		ExpectedWorkload:     cfg.expectedWorkload,
		Backend:              backend,
		SessionTTL:           cfg.sessionTTL,
		SessionMaxAge:        cfg.sessionMaxAge,
	})

	addr := cfg.host + ":" + strconv.Itoa(cfg.port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: cfg.readHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("LB browser-facing endpoints listening", "addr", addr)
	return srv.Serve(ctx, httpSrv)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		slog.Error("unrecognized log level, defaulting to Info", "requested_level", level, "error", err)
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
