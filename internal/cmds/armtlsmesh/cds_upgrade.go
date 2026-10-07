//go:build linux

package armtlsmesh

import (
	"context"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/armtls/cdsclient"
)

// cdsUpgrade swaps the server cert manager's provider from self-signed to
// CDS-issued, retrying with backoff until it succeeds, then upgrades the
// client manager once and flips the cert-mode gauge.
type cdsUpgrade struct {
	logger    *slog.Logger
	logPrefix string
	provider  *cdsclient.Provider

	retryBackoff    time.Duration
	retryMaxBackoff time.Duration
	opTimeout       time.Duration

	serverCertMgr *armtls.CertManager
	clientCertMgr *armtls.CertManager
	metrics       *metrics
}

func (u cdsUpgrade) run(ctx context.Context) {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = u.retryBackoff
	bo.MaxInterval = u.retryMaxBackoff
	// MaxElapsedTime defaults to 0 (unlimited); ctx cancellation is the only
	// exit.

	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		upgradeCtx, cancel := context.WithTimeout(ctx, u.opTimeout)
		defer cancel()
		if err := u.serverCertMgr.SwapProvider(upgradeCtx, u.provider); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	},
		backoff.WithBackOff(bo),
		backoff.WithNotify(func(err error, d time.Duration) {
			u.logger.Warn(u.logPrefix+" certificate upgrade attempt failed (will retry)", "error", err, "backoff", d)
		}),
	)
	if err != nil {
		// ctx cancelled or unrecoverable error from the operation.
		return
	}
	u.logger.Info(u.logPrefix + " certificate upgraded from self-signed to cds-issued (server)")

	if u.clientCertMgr != nil {
		upgradeCtx, cancel := context.WithTimeout(ctx, u.opTimeout)
		if err := u.clientCertMgr.SwapProvider(upgradeCtx, u.provider); err != nil {
			u.logger.Warn(u.logPrefix+" client certificate upgrade failed", "error", err)
		} else {
			u.logger.Info(u.logPrefix + " certificate upgraded from self-signed to cds-issued (client)")
		}
		cancel()
	}

	u.metrics.certMode.Store(1)
}
