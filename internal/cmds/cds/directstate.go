package cds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/cdsdirect"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
)

func newDirectReplica(ctx context.Context, cfg config, st stores) (backend, error) {
	if cfg.allowlistPersistent {
		return nil, errors.New("direct-state pilot requires disposable local storage")
	}
	running, cancel := context.WithCancel(ctx)
	launch := sha256.Sum256(cfg.measuredFile)
	n, err := cdsdirect.New(running, cdsobject.Config{
		Launch:  cdsha.Launch{ClusterID: cfg.measured.ClusterID, OperatorKeys: cfg.measured.OperatorKeys.Keys(), ConfigSHA256: hex.EncodeToString(launch[:]), Voters: cfg.measured.HA.Voters},
		Storage: *cfg.measured.HA.ObjectWALPilot, Allowlist: st.allowlist, Secrets: st.secrets, Ledger: st.bindings,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	ended := make(chan struct{})
	go func() { defer close(ended); n.Run(running) }()
	r := &clusterCDS{handles: handles{allowlist: n.Allowlist(), secrets: n.Secrets(), bindings: n.Bindings()},
		challengePools: challengePools{
			issuance: attestation.NewSharedChallenges(challengeIssuance, cfg.challengeTTL, clusterKey(n, challengeIssuance)),
			secrets:  attestation.NewSharedChallenges(challengeSecrets, cfg.challengeTTL, clusterKey(n, challengeSecrets)),
		}, node: n, stopNode: func() { cancel(); <-ended }, ended: ended,
		extraRoutes: map[string]http.HandlerFunc{
			"POST " + objectProvisionPath:    provisionObjectWAL(n),
			"GET " + objectStatsPath:         reportJSON(n.Stats),
			"GET " + cdsrecovery.RequestPath: n.ServeRecoveryRequest,
		},
	}
	if err := r.join(ctx, cfg); err != nil {
		r.Stop()
		return nil, err
	}
	return r, nil
}
