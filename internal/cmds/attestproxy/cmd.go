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
)

type config struct {
	socket            string
	socketGID         int
	upstream          string
	healthAddr        string
	readHeaderTimeout time.Duration
}

// NewCmd returns the attest-proxy subcommand. It runs as a sidecar in the
// attestation-api DaemonSet pod, publishing the pod-loopback API on the
// node-local socket.
func NewCmd() *cobra.Command {
	var cfg config
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
	f.StringVar(&cfg.healthAddr, "health-addr", "", "TCP address serving GET /healthz for the kubelet's probes (empty disables it)")
	f.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultReadHeaderTimeout, "HTTP request-header timeout on the socket listener")
	cmd.AddCommand(newHealthcheckCmd())
	return cmd
}

// newHealthcheckCmd returns the one-shot probe subcommand. The node-CVM
// DaemonSet probes --health-addr instead — a locked node image denies every
// runc exec, so an exec probe can never pass there — but the same check as a
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
			ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
			defer cancel()
			if _, err := remote.NewClient("unix://" + socket).Health(ctx); err != nil {
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
		Handler:           proxy,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
	}
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

	// Started after the socket is bound so a probe never passes before the
	// front door is up.
	if cfg.healthAddr != "" {
		addr, err := cmdsutil.ServeInBackground(ctx, cfg.healthAddr, healthHandler(cfg.socket), slog.Default())
		if err != nil {
			return fmt.Errorf("--health-addr: %w", err)
		}
		slog.Info("attestation proxy health endpoint listening", "addr", addr)
	}

	slog.Info("attestation proxy listening", "socket", cfg.socket, "upstream", cfg.upstream)
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// healthHandler answers the kubelet's HTTP probe by running the healthcheck
// subcommand's check in process: a GET /health round-trip over the proxy's own
// socket, which covers socket, proxy and upstream at once. The response body
// carries no evidence, so exposing it on the pod IP adds no reachable surface
// beyond "is this DaemonSet serving".
func healthHandler(socket string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), healthcheckTimeout)
		defer cancel()
		if _, err := remote.NewClient("unix://" + socket).Health(ctx); err != nil {
			slog.Warn("attestation proxy healthcheck failed", "socket", socket, "error", err)
			http.Error(w, "attestation-api unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
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
