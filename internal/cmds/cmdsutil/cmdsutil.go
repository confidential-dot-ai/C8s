// Package cmdsutil holds tiny helpers shared across the C8s subcommand
// packages under internal/cmds/. Anything bigger belongs in pkg/.
package cmdsutil

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// RunMain is the body of the per-binary thin shim under cmd/<name>/main.go.
// It calls run with os.Args[1:], prints any error to stderr, and exits with
// status 1 on failure. Each shim collapses to: cmdsutil.RunMain(pkg.Run).
func RunMain(run func([]string) error) {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ValidateHTTPURL returns an error if u is not an http:// or https:// URL.
// The flagName is interpolated into the error so callers needn't wrap.
func ValidateHTTPURL(flagName, u string) error {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("%s %q must start with http:// or https://", flagName, u)
	}
	return nil
}

// ValidateAttestationAPIURL returns an error if u is not an attestation-api
// URL: http(s):// for a network endpoint, or unix:// plus an absolute socket
// path for the node-local socket the chart wires.
func ValidateAttestationAPIURL(flagName, u string) error {
	if socket, ok := strings.CutPrefix(u, "unix://"); ok {
		if !path.IsAbs(socket) {
			return fmt.Errorf("%s %q must name an absolute socket path after unix://", flagName, u)
		}
		return nil
	}
	return ValidateHTTPURL(flagName, u)
}

// RequireRAMBackedDir returns an error unless dir sits on tmpfs/ramfs
// (fileutil.RequireRAMBacked). The flagName is interpolated into the error so
// callers needn't wrap. Shared by get-secret (--out-dir) and get-cert
// (--key-out): each secret-writing sidecar gets the same refusal shape.
func RequireRAMBackedDir(flagName, dir string) error {
	root, err := OpenRAMBackedDir(flagName, dir)
	if err != nil {
		return err
	}
	return root.Close()
}

// OpenRAMBackedDir opens dir, verifies the filesystem behind that open handle
// is RAM-backed, then returns the still-open root. Secret writers must use the
// returned root for every write so replacing dir's pathname cannot redirect
// bytes after verification.
func OpenRAMBackedDir(flagName, dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: open %s: %w", flagName, dir, err)
	}
	if err := fileutil.RequireRAMBackedRoot(root); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	return root, nil
}

// ParseFlags is the standard fs.Parse(args) call used by every Run-style
// subcommand. Help output is redirected to stdout so `c8s <name> --help`
// matches the cobra convention. The returned flag.ErrHelp must still bubble
// up so callers stop before running post-parse validation/startup.
func ParseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(os.Stdout)
	return fs.Parse(args)
}

// ShutdownOnDone blocks on ctx, then triggers srv.Shutdown with a fresh
// timeout-bounded context so the in-flight request drain is independent of
// the cancelled parent. Intended to run in a goroutine.
func ShutdownOnDone(ctx context.Context, srv *http.Server, timeout time.Duration) {
	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}

// ServeInBackground binds addr, serves handler on it from a goroutine and
// shuts the server down when ctx is done. It returns the bound address, so
// ":0" works in tests.
//
// The bind happens here, not in the goroutine. The sidecars use this for the
// probe endpoints that replace exec probes on a locked node image: one that
// failed to bind would leave the pod failing its probes with the cause buried
// in a log line, while an error at startup crashes the container where the
// kubelet reports it.
func ServeInBackground(ctx context.Context, addr string, handler http.Handler, logger *slog.Logger) (net.Addr, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go ShutdownOnDone(ctx, srv, 5*time.Second)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listener failed", "addr", listener.Addr(), "error", err)
		}
	}()
	return listener.Addr(), nil
}

// WarnIfCDSUnpinned warns when a sidecar talks to CDS without launch measurements.
//
// An empty set accepts any armTLS-attested CDS. "No pinning" is a supported
// development shape (`c8s install --measurements` documents empty as UNSAFE),
// so it stays a warning. Shared by get-cert, get-secret and get-volume: three
// copies of this decision would be three chances to drift.
func WarnIfCDSUnpinned(measurementCount int, warn string) {
	if measurementCount <= 0 {
		slog.Warn(warn)
	}
}
