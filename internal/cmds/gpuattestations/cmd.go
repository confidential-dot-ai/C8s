// Package gpuattestations serves the router's snapshot of worker boot evidence.
package gpuattestations

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/readutil"
)

const publicPath = "/.well-known/c8s/gpu-attestations"

func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gpu-attestations",
		Short: "Serve worker GPU boot attestations to the router",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return run(cmd.Context()) },
	}
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func run(ctx context.Context) error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("worker discovery configuration: %w", err)
	}
	cfg.Proxy = http.ProxyURL(nil)
	cfg.Timeout = 10 * time.Second
	api, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return fmt.Errorf("worker discovery client: %w", err)
	}
	api.CheckRedirect = refuseRedirect
	relay := &http.Client{
		Transport:     &http.Transport{},
		Timeout:       workerTimeout,
		CheckRedirect: refuseRedirect,
	}
	defer relay.CloseIdleConnections()
	c := &collector{
		nodesURL: fmt.Sprintf("%s/api/v1/nodes?limit=%d", cfg.Host, maxNodes),
		api:      api,
		relay:    relay,
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.poll(ctx)
	server := &http.Server{
		Addr:              "127.0.0.1:8803",
		Handler:           c,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	go cmdsutil.ShutdownOnDone(ctx, server, 5*time.Second)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type collector struct {
	nodesURL   string
	api, relay *http.Client
	snapshot   atomic.Pointer[snapshot]
	nextWorker string
}

func (c *collector) poll(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		c.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *collector) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()
	snap, err := c.collect(ctx)
	if err != nil {
		snap = &snapshot{failure: "worker discovery failed"}
		switch {
		case errors.Is(err, errDiscoveryLimit), errors.Is(err, readutil.ErrTooLarge):
			snap.failure = errDiscoveryLimit.Error()
		case errors.Is(err, errSnapshotLimit):
			snap.failure = errSnapshotLimit.Error()
		}
		slog.Warn("worker GPU attestation refresh failed", "error", err)
	}
	c.snapshot.Store(snap)
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.EscapedPath() != publicPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	snap := c.snapshot.Load()
	if snap == nil {
		http.Error(w, "worker inventory is initializing", http.StatusServiceUnavailable)
		return
	}
	if snap.failure != "" {
		http.Error(w, snap.failure, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Last-Modified", snap.refreshed.UTC().Format(http.TimeFormat))
	snap.write(w, time.Now())
}
