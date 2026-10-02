package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
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
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func run(cfg config) error {
	logger, err := certutil.NewJSONLogger(cfg.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", cfg.attestationApiURL); err != nil {
		return err
	}
	dnsPatterns, err := compileDNSPatterns(cfg.dnsSANPatterns, cfg.dnsSANFile)
	if err != nil {
		return err
	}
	// Resolve before validateConfig: the secrets predicate reads the flat
	// lists, so a config-mode start must fill them first.
	pinned, err := cmdsutil.LoadImagePolicyValues(cmdsutil.ImagePolicyValuesConfig{
		Source:       cmdsutil.ImagePolicySource{File: cfg.measurementsConfig},
		Pins:         cmdsutil.MeasurementPins{Measurements: cfg.measurements, Registers: cfg.rtmrs},
		Platform:     cfg.ratlsPlatform,
		PlatformFlag: "--ratls-platform",
	})
	if err != nil {
		return err
	}
	if !pinned.Empty() {
		digests, common, _ := pinned.Flatten()
		cfg.measurements = digests
		cfg.rtmrs = refvalues.FormatRegisterPins(common)
		slog.Info("image policy loaded", "tee", pinned.Family, "images", len(pinned.Images))
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	// Empty stays empty: it selects the plain-HTTP path below.
	if family, err := teetypes.ParseFamily(cfg.ratlsPlatform); err == nil {
		cfg.ratlsPlatform = family.String()
	}

	challengeLimiter, err := issuer.NewIPRateLimiter(rate.Limit(cfg.rateLimit), cfg.rateBurst, cfg.rateLimiterMax)
	if err != nil {
		return fmt.Errorf("challenge rate limiter: %w", err)
	}
	rateLimiter, err := issuer.NewIPRateLimiter(rate.Limit(cfg.rateLimit), cfg.rateBurst, cfg.rateLimiterMax)
	if err != nil {
		return fmt.Errorf("init rate limiter: %w", err)
	}

	var writeAuthorizer allowlist.WriteAuthorizer = func(*http.Request, []byte) error {
		return fmt.Errorf("operator writes are disabled: set --operator-keys")
	}
	var operatorKeysPEM []byte
	var operatorKeysHash string
	if cfg.operatorKeys != "" {
		keys, pemBytes, err := loadOperatorKeys(cfg.operatorKeys)
		if err != nil {
			return err
		}
		operatorKeysHash, err = operatorauth.KeySetHash(keys)
		if err != nil {
			return fmt.Errorf("hash --operator-keys %q: %w", cfg.operatorKeys, err)
		}
		operatorKeysPEM = pemBytes
		writeAuthorizer = operatorauth.Verifier{
			Keys:      keys,
			ClockSkew: time.Duration(cfg.jwtClockSkew) * time.Second,
		}.Authorize
		slog.Info("operator write authorization enabled (pinned operator keys)", "operator_keys", cfg.operatorKeys, "count", len(keys), "key_set_hash", operatorKeysHash)
	} else {
		slog.Warn("--operator-keys empty: allowlist and secret writes are disabled (reads still served)")
	}

	allowlistStore, err := allowlist.OpenStore(cfg.allowlistDB)
	if err != nil {
		return fmt.Errorf("open allowlist database: %w", err)
	}
	defer allowlistStore.Close()

	// CDS generates its mesh CA in process at startup; the private key never
	// touches a Kubernetes Secret.
	mesh, err := issuer.NewCAWithCurve(cfg.caCommonName, cfg.caCertValidity, elliptic.P384())
	if err != nil {
		return fmt.Errorf("generate mesh CA: %w", err)
	}
	slog.Info("generated in-memory mesh CA",
		"fingerprint", certutil.CertFingerprint(mesh.Cert.Raw),
		"not_after", mesh.Cert.NotAfter.Format(time.RFC3339),
	)
	caChainPEM := certutil.EncodeCertPEM(mesh.Cert.Raw)
	if err := allowlistStore.StartJournal(authorityFingerprint(mesh.Cert.RawSubjectPublicKeyInfo)); err != nil {
		return fmt.Errorf("start allowlist journal: %w", err)
	}

	measurements := parseReferenceDigests(cfg.measurements)
	if len(measurements) == 0 {
		slog.Warn("--measurements empty: /attest accepts any TEE measurement. UNSAFE outside development.")
	} else {
		slog.Info("measurement pinning enabled for /attest", "count", len(measurements))
	}
	rtmrPins, err := refvalues.ParseRegisterPins(cfg.rtmrs)
	if err != nil {
		return fmt.Errorf("--rtmrs: %w", err)
	}
	if len(rtmrPins) > 0 {
		slog.Info("TDX RTMR pinning enabled for /attest", "count", len(rtmrPins))
	} else if len(measurements) > 0 {
		slog.Warn("--rtmrs empty: on TDX the measurement allowlist pins TDVF firmware only (MRTD); the guest kernel and rootfs are not pinned. SNP is unaffected.")
	}

	// Served at /measurements so a verifier holding the operator's own file can
	// detect a swapped config. Built from the enforced values, never re-read
	// from disk: re-reading would attest the file rather than the policy.
	served := pinned
	if served.Empty() {
		served = refvalues.FromFlags(measurementBytes(measurements), rtmrPins)
	}
	served.Family = servedFamily(cfg.ratlsPlatform)
	measurementsDoc, err := refvalues.Render(served)
	if err != nil {
		return fmt.Errorf("render /measurements document: %w", err)
	}
	cnPattern, err := compilePattern("--allowed-cn-pattern", cfg.allowedCNPattern)
	if err != nil {
		return err
	}

	asClient := remote.NewClient(cfg.attestationApiURL)
	challengeStore := attestation.NewChallengeStore(cfg.challengeTTL)
	// A separate pool for /secrets: sharing one would make a nonce minted for
	// issuance redeemable against a secret, and vice versa.
	secretsChallenges := attestation.NewChallengeStore(cfg.challengeTTL)
	checker := readiness.NewChecker(asClient, cfg.readinessInterval)

	// Seed before serving so the first GET /allowlist returns the bootstrap
	// allowlist (CDS, attestation-api, system images) rather than an empty
	// set; an unseeded store would deny every worker pull until an operator
	// populated it. Fail closed on any seed error.
	if cfg.allowlistSeed != "" {
		if err := seedStore(&allowlistStore, cfg.allowlistSeed); err != nil {
			return fmt.Errorf("seed allowlist: %w", err)
		}
	}

	if !cfg.allowlistPersistent {
		slog.Warn("allowlist store is not persistent (cds.persistence.enabled=false): a restart resets the served allowlist to the install seed and regenerates the mesh CA. Operator-added digests do not survive")
	}

	policy := issuer.CSRPolicy{
		DNSSANPatterns:   dnsPatterns,
		AllowedCNPattern: cnPattern,
	}

	// The sandbox-digests callback: at issuance CDS asks the inventory that
	// admitted a pod what the pod is running (docs/ratls.md, "Sandbox
	// identity"). Pins the same measurement allowlist as /attest, so the
	// inventory answering is held to the standard its RA-TLS certificate already met.
	//
	// Needs an RA-TLS identity of its own, since inventories require a client
	// certificate; without --ratls-platform there is none, and a request
	// carrying a sandbox token is refused rather than issued unchecked. An
	// empty --measurements does NOT disable the callback: it tracks the same
	// posture /attest already takes above, so a dev cluster still issues
	// sandbox-bound leaves (and can still receive secrets) instead of failing
	// every workload.
	inventoryHosts, err := buildInventoryHosts(ctx, cfg.inventoryCIDRs, cfg.kubeconfig)
	if err != nil {
		return err
	}

	var sandboxDigests *workloadclaims.DigestsClient
	if cfg.ratlsPlatform == "" {
		slog.Warn("no --ratls-platform: CDS cannot call inventories back for sandbox digests, so requests carrying a sandbox token will be refused")
	} else {
		if len(measurements) == 0 {
			slog.Warn("--measurements empty: CDS accepts ANY RA-TLS-attested inventory as the source of a sandbox's container digests, so the issuance-time allowlist gate rests on an unpinned peer. UNSAFE outside development.")
		}
		measurementBytes, mErr := measurementDigests(measurements)
		if mErr != nil {
			return mErr
		}
		sandboxDigests, err = workloadclaims.NewDigestsClient(
			ctx,
			cfg.ratlsPlatform,
			attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.attestationApiURL),
			cfg.attestationApiURL,
			ratls.Pins{Measurements: measurementBytes, Registers: rtmrPins, Images: pinned.Images},
			cfg.requestTimeout,
		)
		if err != nil {
			return err
		}
	}

	// The ledger is written on every issuance, not only when secrets are on:
	// enabling the feature later would otherwise start with an empty ledger and
	// fail closed for every pod until its certificate next renews.
	sandboxBindings := sandboxledger.New(issuer.CapTTL(cfg.certTTL, issuer.MaxLeafTTL), cfg.sandboxLedgerMax)
	go sandboxBindings.EvictionLoop(ctx.Done(), cfg.rateLimiterEvictInterval)

	var (
		secretsHandler  *secrets.Handler
		secretsOperator *secrets.OperatorHandler
		secretsExplain  *secrets.ExplainHandler
	)
	if enabled, why := secretsEnabled(cfg, sandboxDigests, inventoryHosts); enabled {
		// One store behind both handlers: an operator write and a workload read
		// are two doors onto the same paths.
		store := newSecretsStore(cfg)
		policy := secrets.NewCachedPolicy(&allowlistStore)
		secretsHandler = &secrets.Handler{
			Store:          store,
			Challenges:     &secretsChallenges,
			Inventory:      sandboxDigests,
			Bindings:       sandboxBindings,
			Policy:         policy,
			InventoryHosts: inventoryHosts,
			Logger:         slog.Default(),
		}
		secretsOperator = &secrets.OperatorHandler{
			Store:        store,
			Authorize:    writeAuthorizer,
			MaxBodyBytes: allowlistWriteBodyCap,
			Logger:       slog.Default(),
		}
		// The same inventory, binding and policy the release path reads, so the
		// diagnostic answers about the decision rather than about a copy of it.
		secretsExplain = &secrets.ExplainHandler{
			Inventory:      sandboxDigests,
			Bindings:       sandboxBindings,
			Policy:         policy,
			InventoryHosts: inventoryHosts,
			Authorize:      writeAuthorizer,
			Logger:         slog.Default(),
		}
		slog.Info("serving /secrets; release is gated on an allowlist entry carrying a secrets grant")
	} else {
		slog.Warn("NOT serving /secrets: any workload depending on a secret will fail to start", "reason", why)
	}

	deps := dependencies{
		AttestHandler: AttestHandler{
			Challenges:        &challengeStore,
			AttestationClient: asClient,
			CA:                mesh,
			CAChainPEM:        caChainPEM,
			CertTTL:           cfg.certTTL,
			NamedCertTTL:      cfg.namedCertTTL,
			RequestTimeout:    cfg.requestTimeout,
			Measurements:      measurements,
			RTMRs:             rtmrPins,
			Images:            pinned.Images,
			SANValidation:     cfg.sanValidation,
			Policy:            policy,
			AllowlistStore:    &allowlistStore,
			PolicySnapshots:   &policySnapshotCache{},
			SandboxDigests:    sandboxDigests,
			InventoryHosts:    inventoryHosts,
			SandboxBindings:   sandboxBindings,
		},
		AllowlistHandler: allowlist.Handler{
			Store:             &allowlistStore,
			WriteAuthorizer:   writeAuthorizer,
			MaxWriteBodyBytes: allowlistWriteBodyCap,
		},
		ReadyFn:           readinessFn(checker.Ready, mesh.Cert, cfg.minCAValidity),
		CACertPEM:         caChainPEM,
		OperatorKeysPEM:   operatorKeysPEM,
		MeasurementsDoc:   measurementsDoc,
		RateLimiter:       rateLimiter,
		ChallengeLimiter:  challengeLimiter,
		MaxRequestSize:    cfg.maxRequestSize,
		SecretsHandler:    secretsHandler,
		SecretsChallenges: &secretsChallenges,
		SecretsOperator:   secretsOperator,
		SecretsExplain:    secretsExplain,
		StateKey:          mesh.Key,
	}
	go rateLimiter.EvictionLoop(ctx, cfg.rateLimiterEvictInterval, cfg.rateLimiterIdleTimeout)
	go challengeLimiter.EvictionLoop(ctx, cfg.rateLimiterEvictInterval, cfg.rateLimiterIdleTimeout)

	router := newRouter(deps)

	go checker.Run(ctx)

	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)
	srv := newHTTPServer(addr, router, cfg)

	if cfg.ratlsPlatform != "" {
		attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.attestationApiURL)
		serverCfg := &ratls.ServerConfig{
			Platform:   cfg.ratlsPlatform,
			AttestFunc: attestFunc,
			CertTTL:    cfg.ratlsCertTTL,
			Logger:     slog.Default(),
		}
		// /secrets reads a CDS-stamped field out of the caller's leaf, so the
		// chain has to be verified by crypto/tls against the mesh CA: the
		// RA-TLS path would admit a self-signed peer whose sandbox-ID extension
		// is whatever it chose. VerifyClientCertIfGiven keeps every other route
		// reachable by a caller with no certificate.
		serverCfg.ClientCAs = []*x509.Certificate{mesh.Cert}
		serverCfg.ClientAuth = tls.VerifyClientCertIfGiven
		tlsCfg, certMgr, err := ratls.NewServerTLSConfig(serverCfg)
		if err != nil {
			return fmt.Errorf("ratls server config: %w", err)
		}
		srv.TLSConfig = tlsCfg

		warmupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = certMgr.WarmUp(warmupCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("warm up ratls serving cert: %w", err)
		}

		go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

		slog.Info("cds listening (RA-TLS)", "addr", addr, "platform", cfg.ratlsPlatform)
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	slog.Warn("RA-TLS disabled (--ratls-platform empty); serving plain HTTP. UNSAFE outside tests.")
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

	slog.Info("cds listening", "addr", addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
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
// tcpSocket probes (the only probe shape a mutual RA-TLS port supports) open
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
func secretsEnabled(cfg config, sandboxDigests *workloadclaims.DigestsClient, inventoryHosts workloadclaims.InventoryHosts) (bool, string) {
	switch {
	case sandboxDigests == nil:
		return false, "no --ratls-platform, so CDS has no attested channel to an inventory"
	case inventoryHosts == nil || inventoryHosts.Empty():
		return false, "the inventory callback has no node addresses to bound it"
	case len(cfg.measurements) == 0:
		return false, "no --measurements, so any TEE could answer as a sandbox's inventory"
	}
	return true, ""
}

func validateConfig(cfg config) error {
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
	// Not "0 disables": this is the stale-identity bound for a named leaf, and
	// 0 is the disable idiom elsewhere in the chart, so a zero here would read
	// as "no bound" while silently meaning issuer.MaxNamedLeafTTL.
	if cfg.namedCertTTL <= 0 {
		return fmt.Errorf("--named-cert-ttl must be positive (it bounds how long a leaf may keep asserting a workload name; it cannot be disabled)")
	}
	if cfg.namedCertTTL > issuer.MaxNamedLeafTTL {
		return fmt.Errorf("--named-cert-ttl must not exceed %v (issuer.MaxNamedLeafTTL, the documented stale-identity bound); it can only shorten that ceiling", issuer.MaxNamedLeafTTL)
	}
	if cfg.maxRequestSize <= 0 {
		return fmt.Errorf("--max-request-size must be positive")
	}
	if cfg.readinessInterval <= 0 {
		return fmt.Errorf("--readiness-interval must be positive")
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

// compilePatterns compiles each raw pattern, skipping empties so a stray "" in
// the list does not become a match-nothing rule. Returns nil for no patterns,
// which ValidateCSR treats as "reject any DNS SAN".
func compilePatterns(name string, raws []string) ([]*regexp.Regexp, error) {
	var patterns []*regexp.Regexp
	for _, raw := range raws {
		re, err := compilePattern(name, raw)
		if err != nil {
			return nil, err
		}
		if re != nil {
			patterns = append(patterns, re)
		}
	}
	return patterns, nil
}

// loadOperatorKeys reads the PEM operator public-key bundle used to verify
// operator write tokens, returning both the parsed keys and the raw PEM (served
// back on GET /operator-keys). It fails closed when the file has no EC public
// key so a typo cannot silently disable write authorization.
func loadOperatorKeys(path string) ([]*ecdsa.PublicKey, []byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read --operator-keys: %w", err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("--operator-keys %q: %w", path, err)
	}
	return keys, pemBytes, nil
}

// measurementDigests renders the /attest measurement allowlist as the raw
// digests ratls.VerifyPolicy pins, so the sandbox-digests callback accepts
// exactly the platforms /attest does.
func measurementDigests(allowed map[string]bool) ([][]byte, error) {
	out := make([][]byte, 0, len(allowed))
	for m := range allowed {
		d, err := hex.DecodeString(m)
		if err != nil {
			// Dropping it would silently unpin the callback while /attest still
			// enforces the same entry as a string — two derivations of one
			// allowlist must not be able to disagree.
			return nil, fmt.Errorf("--measurements entry %q is not hex", m)
		}
		out = append(out, d)
	}
	return out, nil
}

func parseReferenceDigests(raw []string) map[string]bool {
	if len(raw) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(raw))
	for _, m := range raw {
		m = issuer.NormalizeMeasurement(m)
		if m != "" {
			allowed[m] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

// readinessFn returns a closure that flips /readyz to 503 when either the
// attestation-api is unhealthy or the loaded mesh CA is within
// minCAValidity of expiry. The CA expiry signal gives operators a window to
// rotate before signing requests start producing leaves that outlive the CA.
func readinessFn(svcReady func() bool, caCert *x509.Certificate, minCAValidity time.Duration) func() bool {
	return func() bool {
		if !svcReady() {
			return false
		}
		if caCert == nil {
			return false
		}
		if minCAValidity > 0 && time.Until(caCert.NotAfter) < minCAValidity {
			return false
		}
		return true
	}
}
