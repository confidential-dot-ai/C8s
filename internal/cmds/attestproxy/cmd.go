// Package attestproxy implements the node-local front door to the
// attestation-api. The attestation-api binds pod loopback only; this proxy
// serves its API on a hostPath Unix socket so only on-node consumers (the
// host NRI plugin, C8s node components, and pods with the socket directory
// mounted in) can request evidence, while nothing routable — another pod, or
// an off-node host — can reach /attest. Reachability is not authorization:
// the socket must stay safe against any on-node caller. Socket ownership and
// mode gate reachability; callers additionally re-check them on every dial
// (attestation-go/remote).
package attestproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/netutil"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	defaultUpstream          = "http://127.0.0.1:8400"
	defaultReadHeaderTimeout = 5 * time.Second
	// upstreamResponseHeaderTimeout bounds the slowest evidence generation.
	upstreamResponseHeaderTimeout = 30 * time.Second
	healthcheckTimeout            = 3 * time.Second
	// defaultRequestTimeout bounds reading and answering one request. It must
	// exceed the slowest /attest: once the body is read, an expiring read
	// deadline cancels the request context and with it the upstream call.
	defaultRequestTimeout = 2 * upstreamResponseHeaderTimeout
	defaultIdleTimeout    = 30 * time.Second
	maxHeaderBytes        = 16 << 10
	// maxConcurrentConns caps accepted sockets and upstream connections alike,
	// well above the node's consumers (CDS, ratls-mesh, sidecars, NRI).
	maxConcurrentConns = 256
	// proxyLivezPath is the one path the proxy answers on its socket itself.
	proxyLivezPath = "/attest-proxy/livez"
)

type config struct {
	socket            string
	socketGID         int
	upstream          string
	healthAddr        string
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
}

// NewCmd returns the attest-proxy subcommand. It runs as a sidecar in the
// attestation-api DaemonSet pod, publishing the pod-loopback API on the
// node-local socket.
func NewCmd() *cobra.Command {
	cfg := config{
		readTimeout:  defaultRequestTimeout,
		writeTimeout: defaultRequestTimeout,
		idleTimeout:  defaultIdleTimeout,
	}
	cmd := &cobra.Command{
		Use:          "attest-proxy",
		Short:        "Serve the pod-local attestation-api on a node-local Unix socket",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.socket, "socket", "", "Unix socket path to serve on (absolute; created 0660, chgrp'd to --socket-gid)")
	f.IntVar(&cfg.socketGID, "socket-gid", workloadclaims.InventorySocketGID, "group that may connect to the socket (0 = keep the process group)")
	f.StringVar(&cfg.upstream, "upstream", defaultUpstream, "attestation-api base URL (the pod-loopback listener in the same pod)")
	f.StringVar(&cfg.healthAddr, "health-addr", "", "TCP address serving the kubelet's probes: /livez, /healthz and /upstream/livez (empty disables it)")
	f.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultReadHeaderTimeout, "HTTP request-header timeout on the socket listener")
	cmd.AddCommand(newHealthcheckCmd())
	return cmd
}

// newHealthcheckCmd returns the one-shot probe subcommand. The node-CVM
// DaemonSet probes --health-addr instead — a locked node image denies every
// runc exec it was not granted, so an exec probe can never pass there — but the same check as a
// command stays useful from a shell on the node.
func newHealthcheckCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:          "healthcheck",
		Short:        "Exit 0 iff GET /health over the socket succeeds",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if socket == "" {
				return fmt.Errorf("--socket is required")
			}
			if err := checkHealth(context.Background(), remote.NewClient("unix://"+socket)); err != nil {
				return fmt.Errorf("healthcheck over %s: %w", socket, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "Unix socket path to probe")
	return cmd
}

func run(cfg config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(ctx, cfg)
}

func runContext(ctx context.Context, cfg config) error {
	proxy, err := newProxy(cfg)
	if err != nil {
		return err
	}
	listener, err := workloadclaims.ListenUnix(cfg.socket, cfg.socketGID)
	if err != nil {
		return err
	}
	return serve(ctx, cfg, proxy, listener)
}

// serve runs proxy on an already-bound listener until ctx is done.
func serve(ctx context.Context, cfg config, proxy http.Handler, listener net.Listener) error {
	defer listener.Close()

	srv := &http.Server{
		Handler:           answerLivez(proxy),
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       cfg.idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

	// Started after the socket is bound so a probe never passes before the
	// front door is up.
	if cfg.healthAddr != "" {
		addr, err := cmdsutil.ServeInBackground(ctx, cfg.healthAddr, healthHandler(cfg.socket, cfg.upstream), slog.Default())
		if err != nil {
			return fmt.Errorf("--health-addr: %w", err)
		}
		slog.Info("attestation proxy health endpoint listening", "addr", addr)
	}

	slog.Info("attestation proxy listening", "socket", cfg.socket, "upstream", cfg.upstream)
	if err := srv.Serve(netutil.LimitListener(listener, maxConcurrentConns)); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// healthHandler serves the kubelet's HTTP probes. The bodies carry no
// evidence, so exposing them on the pod IP adds no reachable surface beyond
// "is this DaemonSet serving".
//   - /livez: attest-proxy's liveness; a GET of proxyLivezPath over its socket,
//     which the proxy answers itself without calling upstream.
//   - /healthz: readiness; a GET /health round-trip over the proxy's socket,
//     as the healthcheck subcommand runs it.
//   - /upstream/livez: the attestation-api's liveness, which the kubelet cannot
//     probe on pod loopback; a GET /health on upstream directly. Any 2xx answer
//     passes whatever its status: that is the API's state to report, not one
//     a restart fixes. The API answers /health with 200 alone.
func healthHandler(
	socket string,
	upstream string,
) http.Handler {
	socketClient := remote.NewClient("unix://" + socket)
	upstreamClient := remote.NewClient(upstream)
	// No keep-alive: each probe must be a fresh accept by the serve loop.
	livezClient := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		if err := pingProxy(r.Context(), livezClient); err != nil {
			slog.Warn("attestation proxy does not answer on its socket", "socket", socket, "error", err)
			http.Error(w, "proxy does not answer", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := checkHealth(r.Context(), socketClient); err != nil {
			slog.Warn("attestation proxy healthcheck failed", "socket", socket, "error", err)
			http.Error(w, "attestation-api unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /upstream/livez", func(w http.ResponseWriter, r *http.Request) {
		if _, err := fetchHealth(r.Context(), upstreamClient); err != nil {
			slog.Warn("attestation-api healthcheck failed", "upstream", upstream, "error", err)
			http.Error(w, "attestation-api unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// checkHealth runs fetchHealth and, like remote.WaitHealthy, counts only
// status "ok" as healthy.
func checkHealth(
	ctx context.Context,
	client remote.Client,
) error {
	health, err := fetchHealth(ctx, client)
	if err != nil {
		return err
	}
	if health.Status != "ok" {
		return fmt.Errorf("health status %q, want \"ok\"", health.Status)
	}
	return nil
}

// fetchHealth runs GET /health within healthcheckTimeout.
func fetchHealth(
	ctx context.Context,
	client remote.Client,
) (remote.HealthResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	return client.Health(ctx)
}

// pingProxy GETs proxyLivezPath through client within healthcheckTimeout.
func pingProxy(
	ctx context.Context,
	client *http.Client,
) error {
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://attest-proxy"+proxyLivezPath, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", proxyLivezPath, resp.Status)
	}
	return nil
}

func newProxy(cfg config) (http.Handler, error) {
	if !path.IsAbs(cfg.socket) {
		return nil, fmt.Errorf("--socket must be an absolute path, got %q", cfg.socket)
	}
	if cfg.readHeaderTimeout <= 0 {
		return nil, fmt.Errorf("--read-header-timeout must be positive")
	}
	if cfg.healthAddr != "" {
		if _, _, err := net.SplitHostPort(cfg.healthAddr); err != nil {
			return nil, fmt.Errorf("--health-addr %q must be host:port: %w", cfg.healthAddr, err)
		}
	}
	target, err := url.Parse(cfg.upstream)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("invalid --upstream %q", cfg.upstream)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("--upstream must use http or https, got scheme %q", target.Scheme)
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: upstreamResponseHeaderTimeout,
		MaxConnsPerHost:       maxConcurrentConns,
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = pr.In.URL.Path
			pr.Out.URL.RawPath = pr.In.URL.RawPath
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("attestation proxy request failed", "method", r.Method, "path", r.URL.Path, "error", err)
			http.Error(w, "attestation-api unavailable", http.StatusBadGateway)
		},
	}
	return proxy, nil
}

// answerLivez answers proxyLivezPath itself and hands every other request to
// proxy, so /livez proves the socket's serve loop without calling upstream.
func answerLivez(proxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == proxyLivezPath {
			fmt.Fprintln(w, "ok")
			return
		}
		proxy.ServeHTTP(w, r)
	})
}
