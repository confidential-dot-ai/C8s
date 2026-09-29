// Package acme implements the router ACME sidecar (`c8s acme`): the in-guest
// public-TLS issuer for the acme front-door mode. It obtains one multi-SAN
// WebPKI certificate for --domains via ACME HTTP-01 (nginx's :80 server
// proxies /.well-known/acme-challenge/ to the loopback challenge listener),
// writes key + chain under --cert-dir, renews at 2/3 lifetime, and reloads
// nginx via SIGHUP after each install. Under a confidential runtime the
// cert-dir is a Memory-medium emptyDir, so the serving key is TEE-held and
// re-issued on pod recreation.
package acme

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

var procRoot = "/proc"

const letsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

type config struct {
	domains       []string
	directoryURL  string
	email         string
	challengePort int
	httpPort      int
	readyPort     int
	certDir       string
	reloadNginx   bool
	logLevel      string

	// Launch-driven inputs (node image): each file overrides its flag.
	domainsFile      string
	emailFile        string
	directoryURLFile string
	fallbackCertDir  string
}

// NewCmd returns the acme subcommand.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "acme",
		Short: "Run the router in-guest ACME sidecar (acme front-door mode)",
		Long: `acme runs beside nginx in the router pod and keeps one multi-SAN WebPKI
certificate for --domains under --cert-dir: cert.pem (full chain) and key.pem.
Issuance uses ACME HTTP-01; nginx's :80 server proxies
/.well-known/acme-challenge/ to the loopback challenge listener. The
certificate is renewed at 2/3 of its lifetime, and nginx is reloaded via
SIGHUP after each install (shareProcessNamespace: true). On start, a
self-signed placeholder is written when no certificate exists, so nginx —
whose config names both files — can start and serve the challenge proxy the
first issuance needs.

The cert-dir also holds the ACME account key. On a Memory-medium emptyDir the
state is lost with the pod and re-issued on recreation; point
--acme-directory-url at a staging directory when testing to stay clear of the
CA's duplicate-certificate limits.

On a node image the inputs come from the signed launch file:
--domains-file, --acme-email-file and --acme-directory-url-file. When the
domains file is empty, no ACME account is used: the sidecar mirrors cert.pem
and key.pem from --fallback-cert-dir (the mesh leaf) into --cert-dir, re-copies
them when they change and reloads nginx.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(cfg)
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&cfg.domains, "domains", nil, "FQDNs the certificate covers (one multi-SAN certificate), repeatable/comma-separated")
	f.StringVar(&cfg.directoryURL, "acme-directory-url", letsEncryptDirectoryURL, "ACME directory URL (point at a staging directory for testing)")
	f.StringVar(&cfg.email, "acme-email", "", "contact email registered with the ACME account")
	f.IntVar(&cfg.challengePort, "challenge-port", 8402, "loopback port answering ACME HTTP-01 challenges (nginx's :80 server proxies /.well-known/acme-challenge/ to it)")
	f.IntVar(&cfg.httpPort, "http-port", 8080, "loopback port of nginx's :80 server, probed round-trip before each order so no validation is sent at a listener that is still starting")
	f.IntVar(&cfg.readyPort, "ready-port", 0, "port serving GET /healthz, and GET /readyz, 200 once cert.pem and key.pem exist (0 disables it). nginx's startup probe uses it: a locked node image denies exec probes")
	f.StringVar(&cfg.certDir, "cert-dir", "/etc/c8s-acme-tls", "directory for cert.pem, key.pem, and the ACME account key")
	f.BoolVar(&cfg.reloadNginx, "reload-nginx", true, "SIGHUP nginx after a certificate install")
	f.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	f.StringVar(&cfg.domainsFile, "domains-file", "", "file with one domain per line, read at start instead of --domains; empty file means no ACME (see --fallback-cert-dir)")
	f.StringVar(&cfg.emailFile, "acme-email-file", "", "file holding --acme-email; an empty file keeps the flag value")
	f.StringVar(&cfg.directoryURLFile, "acme-directory-url-file", "", "file holding --acme-directory-url; an empty file keeps the flag value")
	f.StringVar(&cfg.fallbackCertDir, "fallback-cert-dir", "", "with an empty --domains-file, mirror cert.pem and key.pem from this directory into --cert-dir (re-copied on change, nginx reloaded) instead of using ACME")

	return cmd
}

// loadFiles applies the file-based inputs. It returns true when the domain
// file is empty and the sidecar should mirror --fallback-cert-dir instead.
func loadFiles(cfg *config) (bool, error) {
	if cfg.domainsFile == "" {
		return false, nil
	}
	if len(cfg.domains) > 0 {
		return false, fmt.Errorf("--domains and --domains-file are mutually exclusive")
	}
	data, err := os.ReadFile(cfg.domainsFile)
	if err != nil {
		return false, fmt.Errorf("--domains-file: %w", err)
	}
	cfg.domains = strings.Fields(string(data))
	for _, f := range []struct {
		path   string
		target *string
	}{{cfg.emailFile, &cfg.email}, {cfg.directoryURLFile, &cfg.directoryURL}} {
		if f.path == "" {
			continue
		}
		data, err := os.ReadFile(f.path)
		if err != nil {
			return false, err
		}
		if v := strings.TrimSpace(string(data)); v != "" {
			*f.target = v
		}
	}
	if len(cfg.domains) > 0 {
		return false, nil
	}
	if cfg.fallbackCertDir == "" {
		return false, fmt.Errorf("--domains-file %s is empty and no --fallback-cert-dir is set", cfg.domainsFile)
	}
	return true, nil
}

func validateConfig(cfg *config) error {
	if len(cfg.domains) == 0 {
		return fmt.Errorf("--domains must name at least one FQDN")
	}
	seen := make(map[string]struct{}, len(cfg.domains))
	for _, d := range cfg.domains {
		if err := validateDomain(d); err != nil {
			return fmt.Errorf("--domains: %w", err)
		}
		if _, dup := seen[d]; dup {
			return fmt.Errorf("--domains lists %q twice", d)
		}
		seen[d] = struct{}{}
	}
	if err := cmdsutil.ValidateHTTPURL("--acme-directory-url", cfg.directoryURL); err != nil {
		return err
	}
	if cfg.challengePort < 1 || cfg.challengePort > 65535 {
		return fmt.Errorf("--challenge-port must be between 1 and 65535, got %d", cfg.challengePort)
	}
	if cfg.httpPort < 1 || cfg.httpPort > 65535 {
		return fmt.Errorf("--http-port must be between 1 and 65535, got %d", cfg.httpPort)
	}
	if cfg.httpPort == cfg.challengePort {
		return fmt.Errorf("--http-port and --challenge-port must differ, got %d", cfg.httpPort)
	}
	if cfg.readyPort < 0 || cfg.readyPort > 65535 {
		return fmt.Errorf("--ready-port must be between 0 and 65535, got %d", cfg.readyPort)
	}
	if cfg.readyPort != 0 && (cfg.readyPort == cfg.challengePort || cfg.readyPort == cfg.httpPort) {
		return fmt.Errorf("--ready-port must differ from --challenge-port and --http-port, got %d", cfg.readyPort)
	}
	return nil
}

// validateDomain checks an RFC 1123 hostname.
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("%q exceeds 253 characters", domain)
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(validation.IsDNS1123Label(label)) > 0 {
			return fmt.Errorf("%q is not a valid RFC 1123 hostname", domain)
		}
	}
	return nil
}

func run(cfg config) error {
	logger, err := newLogger(cfg.logLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	mirror, err := loadFiles(&cfg)
	if err != nil {
		return err
	}
	if !mirror {
		if err := validateConfig(&cfg); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(cfg.certDir, 0o700); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reload := func() {
		if !cfg.reloadNginx {
			return
		}
		if err := cmdsutil.ReloadNginx(procRoot, logger); err != nil {
			logger.Error("nginx reload failed", "error", err)
		}
	}
	if mirror {
		return runMirror(ctx, cfg, logger, reload)
	}
	mgr := newManager(cfg.directoryURL, cfg.email, cfg.certDir, cfg.domains, logger, reload)
	mgr.httpPort = cfg.httpPort

	challengeAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.challengePort))
	if _, err := cmdsutil.ServeInBackground(ctx, challengeAddr, mgr.handler(), logger); err != nil {
		return fmt.Errorf("--challenge-port: %w", err)
	}
	if cfg.readyPort != 0 {
		readyAddr := net.JoinHostPort("", strconv.Itoa(cfg.readyPort))
		if _, err := cmdsutil.ServeInBackground(ctx, readyAddr, readyHandler(mgr.certPath(), mgr.keyPath()), logger); err != nil {
			return fmt.Errorf("--ready-port: %w", err)
		}
	}

	logger.Info("acme sidecar running", "domains", cfg.domains, "cert_dir", cfg.certDir)
	mgr.run(ctx)
	logger.Info("shutting down")
	return nil
}

// readyHandler reports whether nginx can start: its configuration names both
// files, so it crashes until the sidecar has written at least the self-signed
// placeholder. The kubelet cannot dial the loopback challenge listener, and a
// locked node image denies the exec probe this replaces, so the check gets its
// own listener on the pod IP. It exposes existence, never content.
func readyHandler(paths ...string) http.Handler {
	mux := http.NewServeMux()
	// Liveness is the process answering; the same shape as the other sidecars.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		for _, path := range paths {
			if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
				http.Error(w, "certificate not written yet", http.StatusServiceUnavailable)
				return
			}
		}
		fmt.Fprintln(w, "ready")
	})
	return mux
}

func newLogger(level string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})), nil
}
