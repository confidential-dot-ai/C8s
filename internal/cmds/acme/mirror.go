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

// mirrorInterval paces the fallback copy once a pair is installed; until then
// the loop polls at mirrorRetry. Tests tighten both.
var (
	mirrorInterval = time.Minute
	mirrorRetry    = 2 * time.Second
)

// runMirror serves the fallback (mesh) certificate when the launch file names
// no public hostname: nginx always reads --cert-dir, so this keeps one nginx
// configuration for both front-door modes. No ACME account is created.
func runMirror(ctx context.Context, cfg config, logger *slog.Logger, reload func()) error {
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
	logger.Info("no ACME domains: mirroring fallback certificate", "from", cfg.fallbackCertDir, "cert_dir", cfg.certDir)
	installed := false
	for {
		changed, err := mirrorOnce(cfg.fallbackCertDir, cfg.certDir)
		if err != nil {
			logger.Warn("fallback certificate not copied", "error", err)
		} else if changed {
			logger.Info("fallback certificate installed")
			// nginx starts only after the first copy (startup probe), so
			// only later copies need a reload.
			if installed {
				reload()
			}
			installed = true
		}
		wait := mirrorInterval
		if !installed {
			wait = mirrorRetry
		}
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return nil
		case <-time.After(wait):
		}
	}
}

// mirrorOnce copies a matching cert.pem/key.pem pair from src into dst when it
// differs from what dst holds. A torn pair (one file renewed, not yet the
// other) fails the key match and waits for the next round.
func mirrorOnce(src, dst string) (bool, error) {
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
