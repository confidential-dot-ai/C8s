// Package attestproxy implements the node-local front door to the
// attestation-api: a Unix socket only on-node consumers (the host NRI plugin,
// C8s node components, and pods with the socket directory mounted in) can
// reach, while nothing routable — another pod, or an off-node host — can reach
// /attest. On the measured node image the API binds loopback and attest-proxy
// publishes it on the socket; in the cloud chart the API binds the socket
// itself and `attest-proxy probes` serves the kubelet's probes for it.
// Reachability is not authorization: the socket must stay safe against any
// on-node caller. Socket ownership and mode gate reachability; callers
// additionally re-check them on every dial (attestation-go/remote).
package attestproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/netutil"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
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
	// well above the node's consumers: the sidecars injected into its pods,
	// the router's helpers and, on an aks or gke node, the NRI plugin.
	maxConcurrentConns = 256
)

type config struct {
	socket            string
	socketGID         int
	upstream          string
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
}

// NewCmd returns the attest-proxy subcommand. It publishes the loopback API on
// the node-local socket as a systemd service on the measured node image.
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runContext(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.socket, "socket", "", "Unix socket path to serve on (absolute; created 0660, chgrp'd to --socket-gid)")
	f.IntVar(&cfg.socketGID, "socket-gid", workloadclaims.InventorySocketGID, "group that may connect to the socket (0 = keep the process group)")
	f.StringVar(&cfg.upstream, "upstream", defaultUpstream, "attestation-api base URL (its loopback listener)")
	f.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultReadHeaderTimeout, "HTTP request-header timeout on the socket listener")
	cmd.AddCommand(newHealthcheckCmd(), newProbesCmd())
	return cmd
}

// newHealthcheckCmd returns the one-shot probe subcommand. The cloud chart
// probes `attest-proxy probes` instead — a locked node image denies every runc
// exec it was not granted, so an exec probe can never pass there — but the
// same check as a command stays useful from a shell on the node.
func newHealthcheckCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:          "healthcheck",
		Short:        "Exit 0 iff GET /health over the socket succeeds",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if socket == "" {
				return fmt.Errorf("--socket is required")
			}
			if err := checkHealth(cmd.Context(), remote.NewClient("unix://"+socket)); err != nil {
				return fmt.Errorf("healthcheck over %s: %w", socket, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "Unix socket path to probe")
	return cmd
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
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       cfg.idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

	slog.Info("attestation proxy listening", "socket", cfg.socket, "upstream", cfg.upstream)
	if err := srv.Serve(netutil.LimitListener(listener, maxConcurrentConns)); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// checkHealth runs fetchHealth and, like remote.WaitHealthy, counts only
// status "ok" as healthy.
func checkHealth(ctx context.Context, client remote.Client) error {
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
func fetchHealth(ctx context.Context, client remote.Client) (remote.HealthResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	return client.Health(ctx)
}

func newProxy(cfg config) (http.Handler, error) {
	if !path.IsAbs(cfg.socket) {
		return nil, fmt.Errorf("--socket must be an absolute path, got %q", cfg.socket)
	}
	if cfg.readHeaderTimeout <= 0 {
		return nil, fmt.Errorf("--read-header-timeout must be positive")
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
