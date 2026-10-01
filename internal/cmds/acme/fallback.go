package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// fallbackInterval paces the copy once a pair is installed; until then the loop
// polls at fallbackRetry. Tests tighten both.
var (
	fallbackInterval = time.Minute
	fallbackRetry    = 2 * time.Second
)

// runFallback serves the fallback (mesh) certificate when the launch file names
// no public hostname: nginx always reads --cert-dir, so this keeps one nginx
// configuration for both front-door modes. No ACME account is created.
func runFallback(ctx context.Context, cfg config, logger *slog.Logger, reload func()) error {
	if cfg.readyPort < 0 || cfg.readyPort > 65535 {
		return fmt.Errorf("--ready-port must be between 0 and 65535, got %d", cfg.readyPort)
	}
	dst := filepath.Join(cfg.certDir, certFile)
	dstKey := filepath.Join(cfg.certDir, keyFile)
	if cfg.readyPort != 0 {
		addr := net.JoinHostPort("", strconv.Itoa(cfg.readyPort))
		if _, err := cmdsutil.ServeInBackground(ctx, addr, readyHandler(dst, dstKey), logger); err != nil {
			return fmt.Errorf("--ready-port: %w", err)
		}
	}
	logger.Info("no ACME domains: serving the fallback certificate", "from", cfg.fallbackCertDir, "cert_dir", cfg.certDir)

	installed := false
	for {
		changed, err := copyFallbackPair(cfg.fallbackCertDir, cfg.certDir)
		switch {
		case err != nil:
			logger.Warn("fallback certificate not copied", "error", err)
		case changed:
			// The cert volume and nginx can survive a sidecar restart. Reload
			// even this process's first copy; nginx may still serve the old pair.
			// The reload callback tolerates nginx not having started yet.
			logger.Info("fallback certificate installed")
			reload()
		}
		if err == nil {
			// An unchanged matching pair is also installed after a restart.
			installed = true
		}

		wait := fallbackRetry
		if installed {
			wait = fallbackInterval
		}
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return nil
		case <-time.After(wait):
		}
	}
}

// copyFallbackPair copies a matching cert.pem/key.pem pair from src into dst
// when it differs from what dst holds. A torn pair (one file renewed, not yet
// the other) fails the key match and waits for the next round.
func copyFallbackPair(src, dst string) (bool, error) {
	cert, err := os.ReadFile(filepath.Join(src, certFile))
	if err != nil {
		return false, err
	}
	key, err := os.ReadFile(filepath.Join(src, keyFile))
	if err != nil {
		return false, err
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return false, fmt.Errorf("fallback pair in %s: %w", src, err)
	}
	oldCert, _ := os.ReadFile(filepath.Join(dst, certFile))
	oldKey, _ := os.ReadFile(filepath.Join(dst, keyFile))
	if bytes.Equal(cert, oldCert) && bytes.Equal(key, oldKey) {
		return false, nil
	}
	if err := fileutil.WriteAtomic(filepath.Join(dst, keyFile), key, 0o600); err != nil {
		return false, err
	}
	if err := fileutil.WriteAtomic(filepath.Join(dst, certFile), cert, 0o644); err != nil {
		return false, err
	}
	return true, nil
}
