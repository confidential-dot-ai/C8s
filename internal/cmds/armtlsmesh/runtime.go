//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/armtls/cdsclient"
)

type meshEnvironment interface {
	// configure supplies routing and listeners and initializes the runtime health server.
	configure(*meshRuntime) *Proxy
	start(context.Context, *meshRuntime)
}

type meshRuntime struct {
	logger                       *slog.Logger
	serverTLS, clientTLS         *tls.Config
	serverCertMgr, clientCertMgr *armtls.CertManager
	metrics                      *metrics
	health                       *healthServer
	healthPort                   int
	healthListener               net.Listener
	rotationTimeout              time.Duration
	proxy                        *Proxy
}

func newMeshRuntime(cfg *armtls.ServerConfig, logger *slog.Logger) (*meshRuntime, error) {
	serverConfig := *cfg
	serverConfig.Logger = logger.With("cert_role", "server")
	serverTLS, serverCertMgr, err := armtls.NewServerTLSConfig(&serverConfig)
	if err != nil {
		return nil, fmt.Errorf("create server TLS config: %w", err)
	}
	clientTLS, clientCertMgr, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{
		Policy:          cfg.ClientPolicy,
		Platform:        cfg.Platform,
		AttestFunc:      cfg.AttestFunc,
		CACert:          cfg.CACert,
		DynamicCACert:   cfg.DynamicCACert,
		CertTTL:         cfg.CertTTL,
		RotationTimeout: cfg.RotationTimeout,
		Logger:          logger.With("cert_role", "client"),
	})
	if err != nil {
		return nil, fmt.Errorf("create client TLS config: %w", err)
	}
	m := newMetrics()
	if len(cfg.ClientPolicy.Policy.Measurements) > 0 {
		m.measurementPinning.Set(1)
	}
	wrapVerify := func(orig func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
		if orig == nil {
			return nil
		}
		return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			err := orig(rawCerts, chains)
			if err != nil {
				m.attestationFailures.Inc()
			}
			return err
		}
	}
	serverTLS.VerifyPeerCertificate = wrapVerify(serverTLS.VerifyPeerCertificate)
	clientTLS.VerifyPeerCertificate = wrapVerify(clientTLS.VerifyPeerCertificate)
	serverCertMgr.SetOnRotationFail(func() {
		m.certRotationFailures.WithLabelValues("server").Inc()
	})
	if clientCertMgr != nil {
		clientCertMgr.SetOnRotationFail(func() {
			m.certRotationFailures.WithLabelValues("client").Inc()
		})
	}
	return &meshRuntime{
		logger: logger, serverTLS: serverTLS, clientTLS: clientTLS,
		serverCertMgr: serverCertMgr, clientCertMgr: clientCertMgr,
		metrics: m, rotationTimeout: cfg.RotationTimeout,
	}, nil
}

func (r *meshRuntime) run(ctx context.Context, env meshEnvironment) error {
	ctx, cancel := context.WithCancel(ctx)
	var rotations sync.WaitGroup
	defer func() {
		cancel()
		rotations.Wait()
		if r.health != nil {
			r.health.ready.Store(false)
		}
	}()
	p := env.configure(r)
	r.proxy = p
	p.serverTLS, p.clientTLS = r.serverTLS, r.clientTLS
	p.logger, p.metrics = r.logger, r.metrics
	p.origDstFunc = defaultOrigDstFunc
	p.bufPool = newBufPool(p.pipeBufferSize)
	listenersReady := make(chan struct{})
	p.onReady = func() {
		close(listenersReady)
	}
	rotations.Go(func() {
		select {
		case <-ctx.Done():
			return
		case <-listenersReady:
		}
		warmupCtx, cancel := context.WithTimeout(ctx, 2*r.rotationTimeout)
		defer cancel()
		if err := r.serverCertMgr.WarmUp(warmupCtx); err != nil {
			r.logger.Error("server certificate warm-up failed", "error", err)
		}
		if r.clientCertMgr != nil {
			if err := r.clientCertMgr.WarmUp(warmupCtx); err != nil {
				r.logger.Error("client certificate warm-up failed", "error", err)
			}
		}
		rotations.Go(func() {
			r.serverCertMgr.RunRotation(ctx)
		})
		if r.clientCertMgr != nil {
			rotations.Go(func() {
				r.clientCertMgr.RunRotation(ctx)
			})
		}
		r.health.ready.Store(ctx.Err() == nil)
	})
	p.onShutdown = func() {
		r.health.ready.Store(false)
	}
	go func() {
		if err := r.health.serve(ctx, fmt.Sprintf(":%d", r.healthPort), r.healthListener); err != nil {
			r.logger.Error("health server error", "error", err)
		}
	}()
	env.start(ctx, r)
	return p.Run(ctx)
}

func (r *meshRuntime) startCDS(ctx context.Context, cfg *cdsclient.Config, upgrade cdsUpgrade, interval time.Duration) bool {
	provider, err := cdsclient.NewProvider(cfg, r.logger)
	if err != nil {
		r.logger.Error(upgrade.logPrefix+" provider creation failed", "error", err)
		return false
	}
	upgrade.logger, upgrade.provider = r.logger, provider
	upgrade.serverCertMgr, upgrade.clientCertMgr = r.serverCertMgr, r.clientCertMgr
	upgrade.metrics = r.metrics
	go upgrade.run(ctx)
	go caBundleRefresh{
		logger: r.logger, logPrefix: upgrade.logPrefix, provider: provider,
		interval: interval, opTimeout: upgrade.opTimeout,
		serverCertMgr: r.serverCertMgr, clientCertMgr: r.clientCertMgr,
	}.run(ctx)
	return true
}
