// Package allowlistproxy implements the loopback proxy used by router to
// publish CDS's allowlist API. The public TLS connection terminates at nginx;
// this process establishes the second trust hop by verifying CDS's armTLS
// serving certificate before forwarding the original request.
package allowlistproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	defaultRequestTimeout    = 30 * time.Second
	defaultReadHeaderTimeout = 5 * time.Second
)

type config struct {
	measurementsConfig string
	host               string
	port               int
	cdsURL             string
	cdsMeasurements    []string
	cdsRTMRs           []string
	attestationAPIURL  string
	requestTimeout     time.Duration
	readHeaderTimeout  time.Duration
}

// What the enforcer mounts for a credentials-role container, each at the one
// compiled path its client reads. Tests point them elsewhere.
var (
	nodeAddressPath = workloadclaims.CDSAddressPath
	nodePinsPath    = workloadclaims.CDSPinsPath
	nodeVerifier    = workloadclaims.AttestationAPISocket
)

// cds is the CDS this proxy dials and the pins it holds it to.
type cds struct {
	url  string
	pins remote.Policy
}

// NewCmd returns the internal allowlist-proxy subcommand used by the router
// chart. It listens only on pod loopback; nginx is the public front door.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:          "allowlist-proxy",
		Short:        "Proxy router allowlist requests to an armTLS-verified CDS",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.host, "host", "127.0.0.1", "listen host (loopback; nginx is the public listener)")
	f.IntVarP(&cfg.port, "port", "p", 8801, "listen port")
	f.StringVar(&cfg.cdsURL, "cds-url", "", "CDS base URL (must use https/armTLS)")
	f.StringSliceVar(&cfg.cdsMeasurements, "cds-measurements", nil, "allowed CDS SHA-384 launch measurement(s), repeatable/comma-separated; empty accepts any attested CDS (unsafe)")
	f.StringSliceVar(&cfg.cdsRTMRs, "cds-rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> CDS must additionally satisfy, repeatable/comma-separated; ignored when CDS presents SNP evidence (empty pins no registers)")
	cmdsutil.BindImagePolicyFlags(f, &cfg.measurementsConfig, nil, "pins the CDS endpoint; excludes --cds-measurements and --cds-rtmrs")
	f.StringVar(&cfg.attestationAPIURL, "attestation-api-url", "", "attestation-api URL used to verify CDS evidence")
	f.DurationVar(&cfg.requestTimeout, "request-timeout", defaultRequestTimeout, "timeout for one request to CDS")
	f.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultReadHeaderTimeout, "HTTP request-header timeout")
	return cmd
}

func run(cfg config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(ctx, cfg, net.Listen)
}

type listenFunc func(network, address string) (net.Listener, error)

func runContext(ctx context.Context, cfg config, listen listenFunc) error {
	addr, err := listenAddress(cfg.host, cfg.port)
	if err != nil {
		return err
	}
	if cfg.readHeaderTimeout <= 0 {
		return fmt.Errorf("--read-header-timeout must be positive")
	}
	handler, err := newHandler(cfg, slog.Default())
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
	}
	listener, err := listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer listener.Close()
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

	slog.Info("router allowlist proxy listening", "addr", addr, "cds_url", cfg.cdsURL)
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func listenAddress(host string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("--port must be between 1 and 65535, got %d", port)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("--host must be a loopback IP, got %q", host)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func newHandler(cfg config, logger *slog.Logger) (http.Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.requestTimeout <= 0 {
		return nil, fmt.Errorf("--request-timeout must be positive")
	}
	resolved, err := cfg.resolveCDS()
	if err != nil {
		return nil, err
	}
	target, err := parseCDSURL(resolved.url)
	if err != nil {
		return nil, err
	}
	if len(resolved.pins.Measurements) == 0 && len(resolved.pins.Images) == 0 {
		logger.Warn("no CDS measurements pinned; accepting any armTLS-attested CDS (unsafe outside development)")
	}
	httpClient, err := armtls.NewVerifyingHTTPClient(armtls.Pins(resolved.pins), cfg.attestationAPIURL)
	if err != nil {
		return nil, fmt.Errorf("CDS armTLS client: %w", err)
	}
	logger.Info("router allowlist proxy verifying CDS", "cds_url", resolved.url)
	proxy := newReverseProxy(target, httpClient.Transport, cfg.requestTimeout, logger)
	return newRouter(proxy), nil
}

// resolveCDS fixes the CDS this proxy dials, the pins it holds it to and the
// verifier that decides them. All three come from one source: while the
// enforcer mounts the node's endpoint, policy and attestation-api for a
// credentials-role container, they are the only source and a flag naming
// another is refused (cmdsutil.ResolveCDSEndpoint, cmdsutil.ResolveCDSPins,
// cmdsutil.RequireNodeVerifier).
func (cfg config) resolveCDS() (cds, error) {
	endpoint, endpointFromNode, err := cmdsutil.ResolveCDSEndpoint(nodeAddressPath, cfg.cdsURL)
	if err != nil {
		return cds{}, err
	}
	pins, pinsFromNode, err := cmdsutil.ResolveCDSPins(nodePinsPath,
		cmdsutil.ImagePolicySource{File: cfg.measurementsConfig},
		cmdsutil.MeasurementPins{
			Measurements: cfg.cdsMeasurements,
			Registers:    cfg.cdsRTMRs,
			Prefix:       "cds-",
		})
	if err != nil {
		return cds{}, err
	}
	if err := cmdsutil.RequireNodeVerifier(nodePinsPath, nodeVerifier, cfg.attestationAPIURL); err != nil {
		return cds{}, err
	}
	if endpointFromNode != pinsFromNode {
		mounted := nodePinsPath
		missing := nodeAddressPath
		if endpointFromNode {
			mounted = nodeAddressPath
			missing = nodePinsPath
		}
		return cds{}, fmt.Errorf("this node provides %s but not %s: a CDS endpoint and the pins it is held to must come from one source", mounted, missing)
	}
	if endpointFromNode {
		return cds{
			url:  cmdsutil.CDSURL(endpoint),
			pins: pins,
		}, nil
	}
	if cfg.cdsURL == "" {
		return cds{}, errors.New("--cds-url is required: no node hands this client a CDS endpoint")
	}
	return cds{
		url:  cfg.cdsURL,
		pins: pins,
	}, nil
}

func parseCDSURL(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("invalid --cds-url %q", raw)
	}
	if target.Scheme != "https" {
		return nil, fmt.Errorf("--cds-url must use https (armTLS), got scheme %q", target.Scheme)
	}
	if target.User != nil || (target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.Fragment != "" {
		return nil, fmt.Errorf("--cds-url must be an origin without credentials, path, query, or fragment")
	}
	return target, nil
}

func newRouter(proxy http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/allowlist", proxy)
	mux.Handle("/allowlist/", proxy)
	return mux
}

func newReverseProxy(target *url.URL, transport http.RoundTripper, timeout time.Duration, logger *slog.Logger) http.Handler {
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Change only the destination. Keeping Path, RawPath, and RawQuery
			// byte-for-byte preserves the operator token's method/path binding.
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = pr.In.URL.Path
			pr.Out.URL.RawPath = pr.In.URL.RawPath
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = target.Host
			pr.SetXForwarded()

			// ReverseProxy removes headers named by Connection before Rewrite.
			// Restore Authorization from the trusted inbound request so a client
			// cannot make nginx accept a write that CDS sees without its token.
			if auth := pr.In.Header.Get("Authorization"); auth != "" {
				pr.Out.Header.Set("Authorization", auth)
			} else {
				pr.Out.Header.Del("Authorization")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("allowlist proxy request failed", "method", r.Method, "path", r.URL.Path, "error", err)
			http.Error(w, "CDS unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}
