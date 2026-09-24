package cdsattest

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
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
	cdsStateURL        string
	lbForwardPort      int
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
	f.StringVar(&cfg.upstream, "upstream", "", "backend base URL to forward decrypted traffic to (http:// rides the raTLS mesh; https:// does mTLS). Empty uses an echo backend (demo).")
	f.StringVar(&cfg.upstreamCAFile, "upstream-ca", "", "PEM CA bundle to verify an https upstream (the mesh CA)")
	f.StringVar(&cfg.upstreamCertFile, "upstream-cert", "", "client cert presented to an https upstream (the CDS-issued LB cert)")
	f.StringVar(&cfg.upstreamKeyFile, "upstream-key", "", "client key for --upstream-cert")
	f.StringVar(&cfg.cdsStateURL, "cds-state-url", "", "allowlist-proxy base URL (http://127.0.0.1:<port>). Set, attestation bundles carry CDS's nonce-bound rollout state, sessions are fenced on it, and --upstream must be https with a mesh leaf whose matched-workload stamp names a policy in the bound")
	f.IntVar(&cfg.lbForwardPort, "lb-forward-port", 0, "with --cds-state-url, loopback port on which nginx hands front-door requests to the sidecar, which fences them on the rollout state and forwards them to --upstream (0 disables)")
	f.StringVar(&cfg.upstreamServerName, "upstream-server-name", "", "SNI/verification name for an https upstream")
	return cmd
}

func run(cfg config) error {
	logger := newLogger(cfg.logLevel)

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
	if cfg.cdsStateURL != "" && !strings.HasPrefix(cfg.cdsStateURL, "http://") && !strings.HasPrefix(cfg.cdsStateURL, "https://") {
		return fmt.Errorf("--cds-state-url must be an http:// or https:// URL, got %q", cfg.cdsStateURL)
	}
	if cfg.cdsStateURL != "" && cfg.meshIdentityCAFile == "" {
		return fmt.Errorf("--cds-state-url requires --mesh-identity-ca-file to verify the CDS state")
	}
	var hb *HTTPBackend
	var fence *rollout
	var verifyPeer func(*x509.Certificate) error
	if cfg.cdsStateURL != "" {
		fence = newRollout(cfg.cdsStateURL, cfg.meshIdentityCAFile)
		verifyPeer = fence.verifyPeer
		// A pinned client's envelope holds only for attested receivers.
		if cfg.upstream != "" && !strings.HasPrefix(cfg.upstream, "https://") {
			return fmt.Errorf("--cds-state-url requires an https --upstream")
		}
		cfg.upstreamCAFile = cfg.meshIdentityCAFile
	}
	if cfg.upstream != "" {
		var err error
		hb, err = NewHTTPBackend(cfg.upstream, HTTPBackendOptions{
			TrustedCAFile:  cfg.upstreamCAFile,
			ClientCertFile: cfg.upstreamCertFile,
			ClientKeyFile:  cfg.upstreamKeyFile,
			ServerName:     cfg.upstreamServerName,
			VerifyPeer:     verifyPeer,
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
		Rollout:              fence,
	})

	addr := cfg.host + ":" + strconv.Itoa(cfg.port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: cfg.readHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if fence != nil && hb != nil && cfg.lbForwardPort > 0 {
		forwarder, err := newLBForwarder(fence, hb, logger)
		if err != nil {
			return err
		}
		fwdSrv := &http.Server{
			Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.lbForwardPort)),
			Handler:           forwarder,
			ReadHeaderTimeout: cfg.readHeaderTimeout,
		}
		go cmdsutil.ShutdownOnDone(ctx, fwdSrv, shutdownGrace)
		go func() {
			if err := fwdSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("front-door forwarder stopped", "error", err)
				stop()
			}
		}()
		logger.Info("front-door forwarder listening", "addr", fwdSrv.Addr)
	}

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
