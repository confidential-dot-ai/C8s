package attestproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
)

// newProbesCmd returns the subcommand serving the kubelet's probes for an
// attestation-api that binds the socket itself, which the kubelet cannot
// dial. It only connects to the socket, never binds it.
func newProbesCmd() *cobra.Command {
	var socket, addr string
	cmd := &cobra.Command{
		Use:          "probes",
		Short:        "Serve HTTP probes for the attestation-api on a Unix socket",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !path.IsAbs(socket) {
				return fmt.Errorf("--socket must be an absolute path, got %q", socket)
			}
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("--addr: %w", err)
			}
			return serveProbes(cmd.Context(), listener, socket)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "attestation-api Unix socket path (absolute)")
	cmd.Flags().StringVar(&addr, "addr", ":8401", "TCP address serving /livez, /healthz and /api/livez")
	return cmd
}

// serveProbes serves probesHandler on listener until ctx is done.
func serveProbes(ctx context.Context, listener net.Listener, socket string) error {
	srv := &http.Server{
		Handler:           probesHandler(socket),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)
	slog.Info("attestation-api probes listening", "addr", listener.Addr(), "socket", socket)
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// probesHandler serves the kubelet's probes; the bodies carry no evidence.
//   - /livez: the sidecar's liveness. It touches nothing, so neither a hung
//     API nor a missing socket restarts the sidecar, which cannot fix either.
//   - /healthz: readiness, the healthcheck round-trip over the socket.
//   - /api/livez: the attestation-api's liveness. Any 2xx JSON health body
//     passes, since its status is not something a restart fixes; a missing
//     or refusing socket fails, since only the API can bind it again.
func probesHandler(socket string) http.Handler {
	client := remote.NewClient("unix://" + socket)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := checkHealth(r.Context(), client); err != nil {
			slog.Warn("attestation-api readiness check failed", "socket", socket, "error", err)
			http.Error(w, "attestation-api unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /api/livez", func(w http.ResponseWriter, r *http.Request) {
		if _, err := fetchHealth(r.Context(), client); err != nil {
			slog.Warn("attestation-api liveness check failed", "socket", socket, "error", err)
			http.Error(w, "attestation-api unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
}
