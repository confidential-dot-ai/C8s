package cds

import (
	"context"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// application owns process-lifetime clients and limits. dependencies binds
// handlers and their caches to one backend's state.
type application struct {
	cfg              config
	verifier         operatorauth.Verifier
	policy           issuer.CSRPolicy
	attestation      remote.Client
	inventory        sandboxDigestSource
	kms              kmsReleaser
	checker          *readiness.Checker
	rateLimiter      *issuer.IPRateLimiter
	challengeLimiter *issuer.IPRateLimiter
}

func newApplication(
	ctx context.Context,
	cfg config,
	back backend,
	checker *readiness.Checker,
	rateLimiter *issuer.IPRateLimiter,
	challengeLimiter *issuer.IPRateLimiter,
) (*application, error) {
	cnPattern, err := compilePattern(
		"--allowed-cn-pattern",
		cfg.allowedCNPattern,
	)
	if err != nil {
		return nil, err
	}
	nodeImages := separatePodAuthorities(
		back.NodeImages(),
		cfg.measured.PodImages,
	)
	inventory, err := workloadclaims.NewDigestsClient(
		ctx,
		digestsClientConfig(
			cfg,
			nodeImages,
		),
	)
	if err != nil {
		return nil, err
	}
	app := &application{
		cfg: cfg,
		verifier: operatorauth.Verifier{
			Keys:      cfg.measured.OperatorKeys.Keys(),
			ClockSkew: time.Duration(cfg.jwtClockSkew) * time.Second,
		},
		policy: issuer.CSRPolicy{
			DNSSANPatterns:   cfg.measured.DNSSANPatterns,
			AllowedCNPattern: cnPattern,
		},
		attestation:      armtls.NewAttestationClient(cfg.attestationApiURL),
		inventory:        inventory,
		checker:          checker,
		rateLimiter:      rateLimiter,
		challengeLimiter: challengeLimiter,
	}
	if kms := cfg.measured.KMS; kms != nil {
		app.kms = newKMSClient(kms)
	}
	return app, nil
}

// back must share the node-image authority used to construct the inventory
// client. Its stores, challenges and CA may be request-private.
func (a *application) dependencies(back backend) (dependencies, error) {
	cfg := a.cfg
	allowlistWrites := back.Allowlist()
	mesh := back.MeshCA()
	nodeImages := separatePodAuthorities(
		back.NodeImages(),
		cfg.measured.PodImages,
	)
	challengeStore, secretsChallenges := back.Challenges()
	operatorAuthorizer := singleUse(
		a.verifier.AuthorizeIssuedAt,
		allowlistWrites,
		back.TokenFloor,
		time.Duration(cfg.jwtClockSkew)*time.Second,
	)
	inventoryHosts := cfg.measured.NodeCIDRs
	sandboxBindings := back.Bindings()
	deps := dependencies{
		AttestHandler: AttestHandler{
			Challenges:           challengeStore,
			AttestationClient:    a.attestation,
			MeshCA:               mesh,
			CertTTL:              cfg.certTTL,
			NamedCertTTL:         cfg.namedCertTTL,
			RouterCertTTL:        cfg.routerCertTTL,
			RequestTimeout:       cfg.requestTimeout,
			RequireNonMigratable: cfg.measured.ObjectState != nil,
			PodImages:            cfg.measured.PodImages,
			SANValidation:        cfg.sanValidation,
			Policy:               a.policy,
			AllowlistStore:       allowlistWrites,
			PolicySnapshots:      &policySnapshotCache{},
			SandboxDigests:       a.inventory,
			InventoryHosts:       inventoryHosts,
			SandboxBindings:      sandboxBindings,
		},
		AllowlistHandler: allowlist.Handler{
			Allowlist:         allowlistWrites,
			WriteAuthorizer:   operatorAuthorizer,
			MaxWriteBodyBytes: allowlistWriteBodyCap,
		},
		Routes: routeHandler{
			Allowlist: allowlistWrites,
			Authorize: operatorAuthorizer,
		},
		ReadyFn: readinessFn(
			a.checker.Ready,
			back,
			cfg.minCAValidity,
		),
		MeshCA:            mesh,
		ClusterRoutes:     back.ClusterRoutes(),
		OperatorKeysPEM:   cfg.measured.OperatorKeys.PEM(),
		NodeImages:        nodeImages,
		RateLimiter:       a.rateLimiter,
		ChallengeLimiter:  a.challengeLimiter,
		MaxRequestSize:    cfg.maxRequestSize,
		SecretsChallenges: secretsChallenges,
	}
	if enabled, _ := secretsEnabled(
		nodeImages.Current().Images,
		inventoryHosts,
	); enabled {
		policy := secrets.NewCachedPolicy(allowlistWrites)
		deps.SecretsHandler = &secrets.Handler{
			Store:          back.Secrets(),
			Challenges:     secretsChallenges,
			Inventory:      a.inventory,
			Bindings:       sandboxBindings,
			Policy:         policy,
			InventoryHosts: inventoryHosts,
			Logger:         slog.Default(),
		}
		deps.SecretsOperator = &secrets.OperatorHandler{
			Store:        back.Secrets(),
			Authorize:    operatorAuthorizer,
			MaxBodyBytes: allowlistWriteBodyCap,
			Logger:       slog.Default(),
		}
		deps.SecretsExplain = &secrets.ExplainHandler{
			Inventory:      a.inventory,
			Bindings:       sandboxBindings,
			Policy:         policy,
			InventoryHosts: inventoryHosts,
			Authorize:      operatorAuthorizer,
			Logger:         slog.Default(),
		}
	}
	if kms := cfg.measured.KMS; kms != nil {
		broker, err := newSecretBroker(mesh)
		if err != nil {
			return dependencies{}, err
		}
		deps.PodSecrets = &PodSecretHandler{
			Broker: broker,
			KMS:    a.kms,
		}
	}
	return deps, nil
}
