package cds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// caRenewalCheckInterval is how often the renewal loop re-reads the current
// mesh CA certificate.
const caRenewalCheckInterval = 15 * time.Minute

func run(cfg config) error {
	logger, err := certutil.NewJSONLogger(cfg.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.measured.ObjectState != nil {
		return runObjectCDS(ctx, cfg)
	}

	challengeLimiter, err := issuer.NewIPRateLimiter(rate.Limit(cfg.rateLimit), cfg.rateBurst, cfg.rateLimiterMax)
	if err != nil {
		return fmt.Errorf("challenge rate limiter: %w", err)
	}
	rateLimiter, err := issuer.NewIPRateLimiter(rate.Limit(cfg.rateLimit), cfg.rateBurst, cfg.rateLimiterMax)
	if err != nil {
		return fmt.Errorf("init rate limiter: %w", err)
	}

	// The configuration carries at least one operator key, so every CDS
	// authorizes writes under the keys its launch bound.
	operatorKeys := cfg.measured.OperatorKeys
	operatorKeysHash, err := operatorauth.KeySetHash(operatorKeys.Keys())
	if err != nil {
		return fmt.Errorf("hash operator public keys: %w", err)
	}
	slog.Info("operator write authorization enabled (pinned operator keys)", "count", len(operatorKeys.Keys()), "key_set_hash", operatorKeysHash)

	state, err := openStores(cfg)
	if err != nil {
		return err
	}
	defer state.close()

	// What this CDS serves from, chosen once: its own stores and a mesh CA it
	// mints, or the ones its cluster's log carries.
	back, err := newBackend(ctx, cfg, state)
	if err != nil {
		return err
	}
	// Runs before the stores close: a replica applies its cluster's log to them.
	defer back.Stop()
	allowlistWrites := back.Allowlist()
	mesh := back.MeshCA()
	issuing, holdsCA := mesh.Current()
	if !holdsCA {
		return errors.New("this CDS serves no mesh CA, so it could issue nothing")
	}
	slog.Info("serving under a mesh CA",
		"key_id", caKeyID(issuing.CA.Cert),
		"fingerprint", certutil.CertFingerprint(issuing.CA.Cert.Raw),
		"not_after", issuing.CA.Cert.NotAfter.Format(time.RFC3339),
	)

	nodeImages := separatePodAuthorities(back.NodeImages(), cfg.measured.PodImages)
	logNodeImages(nodeImages.Current())

	if _, err := compilePattern(
		"--allowed-cn-pattern",
		cfg.allowedCNPattern,
	); err != nil {
		return err
	}

	asClient := armtls.NewAttestationClient(cfg.attestationApiURL)
	checker := readiness.NewChecker(asClient, cfg.readinessInterval)

	// Seed before serving so the first GET /allowlist returns the bootstrap
	// allowlist (attestation-api, system images) rather than an empty set; an
	// unseeded store would deny every worker pull until an operator populated
	// it. Fail closed on any seed error.
	if err := seedWorkloads(allowlistWrites, cfg.measured.Workloads); err != nil {
		return fmt.Errorf("seed measured workloads: %w", err)
	}

	// C6: there is no route seed; an empty store waits for an operator write.
	if _, err := allowlistWrites.LoadRoutes(); errors.Is(err, allowlist.ErrNoRoutes) {
		slog.Warn("no route manifest stored: write one with 'c8s routes put' or 'c8s routes add'")
	} else if err != nil {
		return err
	}

	if err := allowlistWrites.StartJournal(); err != nil {
		return fmt.Errorf("start allowlist history: %w", err)
	}
	app, err := newApplication(
		ctx,
		cfg,
		back,
		&checker,
		rateLimiter,
		challengeLimiter,
	)
	if err != nil {
		return err
	}
	deps, err := app.dependencies(back)
	if err != nil {
		return err
	}
	if enabled, why := secretsEnabled(
		nodeImages.Current().Images,
		cfg.measured.NodeCIDRs,
	); enabled {
		slog.Info("serving /secrets; release is gated on an allowlist entry carrying a secrets grant")
	} else {
		slog.Warn(
			"NOT serving /secrets: any workload depending on a secret will fail to start",
			"reason",
			why,
		)
	}
	if kms := cfg.measured.KMS; kms != nil {
		slog.Info(
			"serving "+secretbroker.PodRoute+"; pod secret release is brokered to the configured KMS",
			"kms_url",
			kms.URL,
		)
	}
	go rateLimiter.EvictionLoop(ctx, cfg.rateLimiterEvictInterval, cfg.rateLimiterIdleTimeout)
	go challengeLimiter.EvictionLoop(ctx, cfg.rateLimiterEvictInterval, cfg.rateLimiterIdleTimeout)

	// The gate refuses what the state this CDS serves no longer answers for.
	router := back.Gate(newRouter(deps))

	go checker.Run(ctx)

	addr := clientAddress(cfg)
	srv := newHTTPServer(addr, router, cfg)

	tlsCfg, meshPeers, err := armtls.NewServerTLSConfig(servingConfig(cfg, issuing.CA.Cert))
	if err != nil {
		return fmt.Errorf("armtls server config: %w", err)
	}
	srv.TLSConfig = tlsCfg

	warmupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = meshPeers.WarmUp(warmupCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("warm up armtls serving cert: %w", err)
	}
	go meshPeers.RunRotation(ctx)
	slog.Info("cds serving armTLS", "platform", cfg.armtlsPlatform)

	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)
	go back.KeepMeshCA(ctx, meshPeers)

	slog.Info("cds listening", "addr", addr)
	if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func clientAddress(cfg config) string {
	return fmt.Sprintf("%s:%d", cfg.host, cfg.port)
}

func newHTTPServer(addr string, handler http.Handler, cfg config) *http.Server {
	cfg = normalizeHTTPServerConfig(cfg)
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       cfg.readTimeout,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       cfg.idleTimeout,
		MaxHeaderBytes:    cfg.maxHeaderBytes,
		ErrorLog:          log.New(serverLogFilter{}, "", 0),
	}
}

// serverLogFilter routes net/http server error lines to slog. The kubelet's
// tcpSocket probes (the only probe shape a mutual armTLS port supports) open
// the port and drop it every few seconds, which net/http reports as a TLS
// handshake EOF or reset — demote exactly those to debug so real handshake
// faults keep a visible log level.
type serverLogFilter struct{}

func (serverLogFilter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if strings.Contains(msg, "TLS handshake error") &&
		(strings.HasSuffix(msg, ": EOF") || strings.HasSuffix(msg, ": connection reset by peer")) {
		slog.Debug(msg)
	} else {
		slog.Info(msg)
	}
	return len(p), nil
}

func armtlsAttestFunc(cfg config) func(context.Context, string) (string, error) {
	return attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), cfg.attestationApiURL)
}

// servingConfig is CDS's armTLS serving certificate. /secrets reads a
// CDS-stamped field out of the caller's leaf, so the chain has to be verified
// by crypto/tls against the mesh CA: the armTLS path would admit a self-signed
// peer whose sandbox-ID extension is whatever it chose. VerifyClientCertIfGiven
// keeps every other route reachable by a caller with no certificate.
//
// A CDS VM extends no register, so neither this certificate nor the
// sandbox-digests client lists a measured policy.
func servingConfig(cfg config, meshCA *x509.Certificate) *armtls.ServerConfig {
	return &armtls.ServerConfig{
		Platform:             cfg.armtlsPlatform.String(),
		AttestFunc:           armtlsAttestFunc(cfg),
		CertTTL:              cfg.armtlsCertTTL,
		Logger:               slog.Default(),
		ClientCA:             meshCA,
		ClientAuth:           tls.VerifyClientCertIfGiven,
		MeasuredPoliciesFile: "",
	}
}

// digestsClientConfig is the client CDS calls node inventories back with for
// a sandbox's container digests. It holds an inventory to the node images CDS
// certifies, so the two follow one set.
func digestsClientConfig(cfg config, nodeImages armtls.PinSource) (workloadclaims.DigestsClientConfig, error) {
	result := workloadclaims.DigestsClientConfig{
		RequireNonMigratable: cfg.measured != nil && cfg.measured.ObjectState != nil,
		Platform:             cfg.armtlsPlatform.String(),
		AttestFunc:           armtlsAttestFunc(cfg),
		AttestationAPIURL:    cfg.attestationApiURL,
		NodeImages:           nodeImages,
		Timeout:              cfg.requestTimeout,
		MeasuredPoliciesFile: "",
	}
	if cfg.measured != nil && cfg.measured.ObjectState != nil {
		native, err := armtls.NewNativeVerifier(cfg.measured.ObjectState.SNPMinTCB)
		if err != nil {
			return result, err
		}
		result.Native = native
	}
	return result, nil
}

func normalizeHTTPServerConfig(cfg config) config {
	if cfg.readTimeout == 0 {
		cfg.readTimeout = defaultHTTPReadTimeout
	}
	if cfg.readHeaderTimeout == 0 {
		cfg.readHeaderTimeout = defaultHTTPReadHeaderTimeout
	}
	if cfg.writeTimeout == 0 {
		cfg.writeTimeout = defaultHTTPWriteTimeout
	}
	if cfg.idleTimeout == 0 {
		cfg.idleTimeout = defaultHTTPIdleTimeout
	}
	if cfg.maxHeaderBytes == 0 {
		cfg.maxHeaderBytes = defaultHTTPMaxHeaderBytes
	}
	return cfg
}

// newSecretsStore builds the store from sizing flags validateSecretsConfig has
// already checked: NewMemoryStore panics on a pair validateSecretsConfig
// refuses.
func newSecretsStore(cfg config) *secrets.MemoryStore {
	return secrets.NewMemoryStore(cfg.secretsMaxPaths, cfg.secretsMaxPathsPerWorkload, cfg.secretsMaxValueBytes)
}

// validateSecretsConfig checks the bounds on secret storage. What secrets are
// released to is policy, not configuration — see secretsEnabled.
func validateSecretsConfig(cfg config) error {
	if cfg.secretsMaxPaths <= 0 || cfg.secretsMaxPathsPerWorkload <= 0 || cfg.sandboxLedgerMax <= 0 {
		return fmt.Errorf("--secrets-max-paths, --secrets-max-paths-per-workload and --sandbox-ledger-max-entries must be positive")
	}
	if cfg.secretsMaxPathsPerWorkload >= cfg.secretsMaxPaths {
		return fmt.Errorf("--secrets-max-paths-per-workload (%d) must be below --secrets-max-paths (%d), or one workload can fill the store", cfg.secretsMaxPathsPerWorkload, cfg.secretsMaxPaths)
	}
	if cfg.secretsMaxValueBytes < secrets.GeneratedValueBytes {
		return fmt.Errorf("--secrets-max-value-bytes (%d) must be at least %d, the size of every value CDS generates", cfg.secretsMaxValueBytes, secrets.GeneratedValueBytes)
	}
	return nil
}

// secretsEnabled reports whether CDS serves /secrets, and why not when it does
// not.
//
// Release is gated on an allowlist entry carrying a grant, so an entry without
// one releases nothing and mounting the endpoint is inert until an operator
// writes a grant. What this decides is narrower: whether CDS can answer at all,
// which is what sandbox identity already needs.
func secretsEnabled(nodeImages []remote.ImagePin, inventoryHosts workloadclaims.CIDRHosts) (bool, string) {
	switch {
	case len(inventoryHosts) == 0:
		return false, "the inventory callback has no node addresses to bound it"
	case len(nodeImages) == 0:
		return false, "the configuration pins no node identity, so any TEE could answer as a sandbox's inventory"
	}
	return true, ""
}

func logNodeImages(images refvalues.ReferenceValues) {
	slog.Info("node image pinning enabled for /attest", "tee", images.Family, "count", len(images.Images))
	if images.Family != teetypes.FamilyTDX {
		return
	}
	if firmwareOnly := imagesWithoutRegisters(images.Images); len(firmwareOnly) > 0 {
		slog.Warn("these TDX node images pin no RTMR: the pin covers TDVF firmware only (MRTD), and the guest kernel and rootfs are not pinned", "images", firmwareOnly)
	}
}

// imagesWithoutRegisters names the node images pinned by their launch
// measurement alone.
func imagesWithoutRegisters(images []remote.ImagePin) []string {
	var names []string
	for _, image := range images {
		if len(image.Registers) == 0 {
			names = append(names, image.Name)
		}
	}
	return names
}

func validateConfig(cfg config) error {
	if cfg.measured == nil {
		return fmt.Errorf("--config: CDS serves one cluster's measured configuration and was given none")
	}
	if cfg.measured.ObjectState == nil && cfg.allowlistDB == "" {
		return errors.New("--allowlist-db is required without objectState")
	}
	if len(cfg.measured.OperatorKeys.Keys()) == 0 {
		return fmt.Errorf("--config: the configuration pins no operator key, so no policy write could ever be authorized")
	}
	if err := cfg.measured.ValidatePodAuthorities(); err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	for _, timeout := range []struct {
		name  string
		value time.Duration
	}{
		{"--read-timeout", cfg.readTimeout},
		{"--read-header-timeout", cfg.readHeaderTimeout},
		{"--write-timeout", cfg.writeTimeout},
		{"--idle-timeout", cfg.idleTimeout},
	} {
		if timeout.value < 0 {
			return fmt.Errorf("%s must be non-negative", timeout.name)
		}
	}
	if cfg.maxHeaderBytes < 0 {
		return fmt.Errorf("--max-header-bytes must be non-negative")
	}
	if skew := time.Duration(cfg.jwtClockSkew) * time.Second; 2*skew >= allowlist.SpentTokenMargin {
		return fmt.Errorf("--jwt-clock-skew must stay under half of %v, so an operator token the verifier accepts is never refused as a replay", allowlist.SpentTokenMargin)
	}
	// Not "0 disables": this is the stale-identity bound for a named leaf, and
	// 0 is the disable idiom elsewhere in the chart, so a zero here would read
	// as "no bound" while silently meaning issuer.MaxNamedLeafTTL.
	if cfg.namedCertTTL <= 0 {
		return fmt.Errorf("--named-cert-ttl must be positive (it bounds how long a leaf may keep asserting a workload name; it cannot be disabled)")
	}
	if cfg.namedCertTTL > issuer.MaxNamedLeafTTL {
		return fmt.Errorf("--named-cert-ttl must not exceed %v (issuer.MaxNamedLeafTTL, the documented stale-identity bound); it can only shorten that ceiling", issuer.MaxNamedLeafTTL)
	}
	if cfg.routerCertTTL <= 0 || cfg.routerCertTTL >= cfg.allowlistNodeDelay {
		return fmt.Errorf("--router-cert-ttl (%v) must be positive and shorter than --allowlist-node-delay (%v)", cfg.routerCertTTL, cfg.allowlistNodeDelay)
	}
	if cfg.maxRequestSize <= 0 {
		return fmt.Errorf("--max-request-size must be positive")
	}
	if cfg.readinessInterval <= 0 {
		return fmt.Errorf("--readiness-interval must be positive")
	}
	if cfg.minCAValidity <= 0 {
		return fmt.Errorf("--min-ca-validity must be positive (it is the window CA renewal has to succeed in before /readyz fails)")
	}
	// Renewal starts at half the certificate's lifetime and is retried once
	// per check interval, so this is what makes "renewed before the remaining
	// validity falls below --min-ca-validity" hold by construction.
	if cfg.caCertValidity/2 <= cfg.minCAValidity+caRenewalCheckInterval {
		return fmt.Errorf("--ca-cert-validity (%v) must exceed 2 x (--min-ca-validity %v + %v renewal check interval)",
			cfg.caCertValidity, cfg.minCAValidity, caRenewalCheckInterval)
	}
	if err := validateSecretsConfig(cfg); err != nil {
		return err
	}
	return nil
}

func compilePattern(name, raw string) (*regexp.Regexp, error) {
	if raw == "" {
		return nil, nil
	}
	re, err := regexp.Compile(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	return re, nil
}

// readinessFn returns a closure that flips /readyz to 503 unless the
// attestation-api is healthy, the state this CDS serves answers, and its mesh
// CA certificate has more than minCAValidity left — the window renewal has to
// succeed in.
func readinessFn(svcReady func() bool, back backend, minCAValidity time.Duration) func() bool {
	return func() bool {
		if !svcReady() || !back.Ready() {
			return false
		}
		issuing, holdsCA := back.MeshCA().Current()
		return holdsCA && caValidityHolds(issuing.CA.Cert, minCAValidity, time.Now())
	}
}

// caValidityHolds reports whether the certificate has at least minValidity left.
func caValidityHolds(cert *x509.Certificate, minValidity time.Duration, now time.Time) bool {
	return cert.NotAfter.Sub(now) >= minValidity
}

// caKeyID identifies the mesh CA key the process holds: SHA-256 over the SPKI
// DER, which every certificate renewed under that key carries.
func caKeyID(cert *x509.Certificate) string {
	return certutil.CertFingerprint(cert.RawSubjectPublicKeyInfo)
}

// renewMeshCAWhenDue renews the mesh CA certificate under the key the process
// keeps and republishes it to meshPeers, the pool that verifies client leaves;
// a nil meshPeers is a listener with no such pool. A failed renewal is retried
// on the next tick, and readiness drops once the current certificate no longer
// holds --min-ca-validity.
func renewMeshCAWhenDue(ctx context.Context, mesh *issuer.MeshCA, every time.Duration, meshPeers *armtls.CertManager) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !pastHalfLife(mesh.Current().CA.Cert, time.Now()) {
				continue
			}
			renewed, err := mesh.RenewCertificate()
			if err != nil {
				slog.Error("mesh CA certificate renewal failed", "error", err)
				continue
			}
			if meshPeers != nil {
				meshPeers.UpdateClientCA(renewed.CA.Cert)
			}
			slog.Info("renewed mesh CA certificate",
				"audit", true,
				"key_id", caKeyID(renewed.CA.Cert),
				"fingerprint", certutil.CertFingerprint(renewed.CA.Cert.Raw),
				"not_after", renewed.CA.Cert.NotAfter.Format(time.RFC3339),
			)
		}
	}
}

// pastHalfLife is the renewal trigger: half the certificate's lifetime, which
// --ca-cert-validity guarantees leaves room for renewal to retry in before
// readiness fails.
func pastHalfLife(cert *x509.Certificate, now time.Time) bool {
	return now.After(cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2))
}
