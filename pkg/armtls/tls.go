package armtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Logger is an optional structured logger for armTLS operations.
// If nil, no logging occurs. Compatible with [log/slog.Logger].
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// ServerConfig configures an armTLS server.
type ServerConfig struct {
	// Platform is the TEE platform: "sev-snp" or "tdx".
	Platform string

	// AttestFunc generates attestation evidence given custom data
	// (hex-encoded REPORTDATA). This is the sole integration point
	// with the TEE attestation infrastructure. The context comes from
	// the TLS handshake and should be used for cancellation/timeouts.
	AttestFunc func(ctx context.Context, customData string) (string, error)

	// CertProvider, when set, is used instead of Platform/AttestFunc for
	// certificate provisioning. This enables pluggable certificate sources
	// (e.g., CDS-issued certificates). When nil, a SelfSignedProvider is
	// constructed from Platform and AttestFunc.
	CertProvider CertProvider

	// DNSNames for the server certificate.
	DNSNames []string

	// Subject for the certificate. Defaults to "armTLS Workload".
	Subject pkix.Name

	// CertTTL is the certificate lifetime. Default: 24h.
	// The certificate is rotated automatically at 50% of TTL.
	CertTTL time.Duration

	// ClientPolicy, when set, enables mTLS: the server requires client
	// certificates and verifies their armTLS attestation against this policy.
	// When nil, the server does not request client certificates.
	ClientPolicy *VerifyPolicy

	// ClientCA, when set, has crypto/tls verify a presented client certificate
	// against that root: a leaf that does not chain is rejected in the
	// handshake. Mutually exclusive with ClientPolicy, which admits a
	// self-issued armTLS peer — for a handler that reads a CDS-stamped field
	// out of the leaf (the sandbox ID), that would let any attested TEE assert
	// an arbitrary value.
	//
	// Pair it with ClientAuth to choose whether a certificate is required.
	// Because the chain is verified here, r.TLS.VerifiedChains is populated and
	// a handler need not re-verify.
	ClientCA *x509.Certificate

	// ClientAuth selects how a client certificate is demanded when ClientCA is
	// set; it defaults to tls.VerifyClientCertIfGiven, which lets a certless
	// caller still reach the routes that need no identity while holding any
	// certificate that IS presented to the ClientCA root. Ignored unless
	// ClientCA is set.
	ClientAuth tls.ClientAuthType

	// RotationTimeout is the maximum time allowed for background certificate
	// rotation. If the attestation binary doesn't respond within this duration,
	// rotation is aborted and retried on the next handshake past rotateAt.
	// Default: 30s.
	RotationTimeout time.Duration

	// Logger, when set, receives structured log messages for certificate
	// provisioning, rotation, and errors. If nil, no logging occurs.
	Logger Logger
}

// ClientConfig configures an armTLS client that verifies the server's own
// evidence.
type ClientConfig struct {
	// Policy defines acceptable attestation claims for the server. Required:
	// the client verifies the server against it on every handshake.
	Policy *VerifyPolicy

	// Platform and AttestFunc, when both set, enable mTLS: the client
	// presents its own armTLS certificate to the server. Both must be
	// set together or both left unset.
	Platform   string
	AttestFunc func(ctx context.Context, customData string) (string, error)

	// CertProvider, when set, is used instead of Platform/AttestFunc for
	// certificate provisioning. When nil, a SelfSignedProvider is constructed
	// from Platform and AttestFunc (if both are set).
	CertProvider CertProvider

	// CertTTL is the client certificate lifetime. Default: 24h.
	// Only used when Platform and AttestFunc are set.
	CertTTL time.Duration

	// RotationTimeout is the maximum time allowed for background certificate
	// rotation. Default: 30s.
	RotationTimeout time.Duration

	// Logger, when set, receives structured log messages for certificate
	// provisioning, rotation, and errors. If nil, no logging occurs.
	Logger Logger
}

// defaultRotationTimeout bounds a single provisioning round-trip, background
// or synchronous. The synchronous path needs it just as much: it runs under
// GetCertificate, whose context comes from tls.NewListener and therefore
// carries no deadline of its own.
const defaultRotationTimeout = 30 * time.Second

// syncProvisionCooldown is how long a failed synchronous provision is replayed
// from the negative cache before the provider is tried again. Handshakes are
// unbounded in number, so without a cooldown an outage past NotAfter turns
// every inbound connection into another request aimed at the certificate
// source that is already failing.
const syncProvisionCooldown = 5 * time.Second

// certState holds a cached certificate and its rotation deadline.
// Rotation is non-blocking: when a cert is due for rotation, the old cert
// is returned immediately while a background goroutine provisions the new one.
type certState struct {
	mu              sync.RWMutex
	cert            *tls.Certificate
	rotateAt        time.Time
	revision        uint64
	retryAt         time.Time
	retryBackoff    *backoff.ExponentialBackOff
	rotationEnded   chan struct{}
	rotationCancel  context.CancelFunc
	provider        CertProvider // certificate provisioning strategy
	logger          Logger
	rotating        atomic.Bool   // prevents concurrent background rotations
	rotationTimeout time.Duration // 0 = default (defaultRotationTimeout)
	provisioned     atomic.Bool   // true after first successful provision
	onRotationFail  func()        // optional callback on rotation failure (for metrics)
	defaultTTL      time.Duration // fallback TTL if provider returns 0

	// syncMu guards the fail-closed provisioning path's own bookkeeping. It
	// is deliberately not mu: mu is taken by every handshake and by the
	// CertExpiry metrics scrape, so a provisioning round-trip must never be
	// held under it.
	syncMu        sync.Mutex
	inflight      *provisionAttempt // the one synchronous attempt in progress
	cooldownUntil time.Time         // negative cache expiry
	cooldownErr   error             // error replayed until cooldownUntil
	syncCooldown  time.Duration     // 0 = default (syncProvisionCooldown)

	// unusableLogged rate-limits the "cached certificate is outside its
	// validity window" warning to one line per entry into that state. It is
	// on the handshake path, so logging per connection would flood exactly
	// during the outage whose logs matter.
	unusableLogged atomic.Bool
}

// provisionAttempt is one in-flight synchronous provisioning run. Handshakes
// that find the cache unusable join the attempt already running rather than
// each starting their own, so a down certificate source sees one request per
// cooldown window instead of one per connection.
type provisionAttempt struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// CertReady returns true if a certificate has been successfully provisioned
// at least once. Use this to gate readiness probes.
//
// It says nothing about whether that certificate can still be served — see
// [certState.CertUsable].
func (s *certState) CertReady() bool {
	return s.provisioned.Load()
}

// CertUsable reports whether the cached certificate could be handed to a
// handshake right now. CertReady is sticky ("provisioned at least once") and
// since the manager stopped serving certificates outside their validity
// window that no longer implies "can serve TLS": a pod whose certificate
// source has been down past NotAfter fails 100% of its handshakes. Readiness
// gates on this so such a pod leaves the endpoint list instead of
// blackholing traffic.
func (s *certState) CertUsable() bool {
	s.mu.RLock()
	cert := s.cert
	s.mu.RUnlock()
	return cert != nil && usableForHandshake(cert, time.Now()) == nil
}

// CertExpiry returns the NotAfter time of the current certificate, or the zero
// time if no certificate has been provisioned yet.
func (s *certState) CertExpiry() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cert == nil || s.cert.Leaf == nil {
		return time.Time{}
	}
	return s.cert.Leaf.NotAfter
}

// WarmUp eagerly provisions a certificate so the first TLS handshake doesn't
// block on attestation. Returns the cert or an error. Thread-safe.
func (s *certState) WarmUp(ctx context.Context) error {
	_, err := s.getOrProvision(ctx)
	return err
}

// getOrProvision returns a cached certificate or provisions a new one.
// If the cached cert is past its rotation deadline but still valid, the old
// cert is returned immediately and rotation happens in the background.
// A cached cert outside its validity window is never returned: rotateAt only
// schedules replacement, so when background rotation has kept failing the
// expired cert is discarded here and provisioning happens synchronously —
// the handshake gets a fresh cert or an error, never a stale credential.
// Otherwise only the very first call (no cert at all) blocks synchronously.
func (s *certState) getOrProvision(ctx context.Context) (*tls.Certificate, error) {
	// One clock reading for the whole decision: judging the cert usable
	// against one instant and rotation-due against another can serve a cert
	// the very next comparison considers unusable.
	now := time.Now()

	s.mu.RLock()
	cached := s.cert
	rotateAt := s.rotateAt
	currentProvider := s.provider // capture under RLock before releasing
	retryAt := s.retryAt
	revision := s.revision
	s.mu.RUnlock()

	if cached != nil {
		err := usableForHandshake(cached, now)
		switch {
		case err == nil:
			s.unusableLogged.Store(false)
			if now.Before(rotateAt) || now.Before(retryAt) {
				return cached, nil
			}

			// A renewal may install only against the revision that started it.
			s.requestRotation(currentProvider, revision)
			return cached, nil
		case s.logger != nil && s.unusableLogged.CompareAndSwap(false, true):
			s.logger.Warn("armtls: cached certificate is outside its validity window, provisioning synchronously", "err", err)
		}
	}

	// No cert at all, or the cached one is no longer usable — provision
	// synchronously.
	return s.syncProvision(ctx, now)
}

// syncProvision is the fail-closed path: nothing usable is cached, so the
// caller gets a fresh certificate or an error, never a stale credential.
//
// It runs under a TLS handshake, which makes two properties load-bearing.
// First it is single-flighted: N concurrent handshakes against an expired
// cache would otherwise run N serialized provisioning attempts with no
// backoff — a retry storm aimed at the source that is already failing — so
// latecomers wait on the one attempt in progress. Second it is time-bounded,
// by the same timeout background rotation uses, because the handshake context
// comes from tls.NewListener and has no deadline of its own. A failure is
// negative-cached for syncProvisionCooldown so the storm does not resume the
// instant the attempt returns.
func (s *certState) syncProvision(ctx context.Context, now time.Time) (*tls.Certificate, error) {
	if ctx == nil {
		// A zero tls.ClientHelloInfo / tls.CertificateRequestInfo carries no
		// context; the timeout below is what actually bounds this path.
		ctx = context.Background()
	}

	s.syncMu.Lock()

	// Another goroutine may have stored a usable cert while we queued.
	s.mu.RLock()
	cached := s.cert
	s.mu.RUnlock()
	if cached != nil && usableForHandshake(cached, now) == nil {
		s.syncMu.Unlock()
		return cached, nil
	}

	if attempt := s.inflight; attempt != nil {
		s.syncMu.Unlock()
		select {
		case <-attempt.done:
			return attempt.cert, attempt.err
		case <-ctx.Done():
			// Our own handshake went away; the attempt continues for whoever
			// is still waiting on it.
			return nil, ctx.Err()
		}
	}

	if now.Before(s.cooldownUntil) {
		err := s.cooldownErr
		s.syncMu.Unlock()
		return nil, err
	}

	attempt := &provisionAttempt{done: make(chan struct{})}
	s.inflight = attempt
	s.syncMu.Unlock()

	attempt.cert, attempt.err = s.provisionNow(ctx)

	s.syncMu.Lock()
	s.inflight = nil
	// A context cancellation says the caller left, not that the provider is
	// unhealthy, so it must not poison the cache for everyone else.
	if attempt.err != nil && ctx.Err() == nil {
		s.cooldownUntil = time.Now().Add(s.effectiveSyncCooldown())
		s.cooldownErr = attempt.err
	}
	s.syncMu.Unlock()
	close(attempt.done)

	return attempt.cert, attempt.err
}

// provisionNow runs one bounded provisioning round-trip and, on success,
// stores the result as the cached certificate.
func (s *certState) provisionNow(ctx context.Context) (*tls.Certificate, error) {
	s.mu.RLock()
	provider := s.provider
	revision := s.revision
	s.mu.RUnlock()

	pctx, cancel := context.WithTimeout(ctx, s.effectiveRotationTimeout())
	defer cancel()

	cert, ttl, err := provider.Provision(pctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("armtls: certificate provisioning failed", "err", err)
		}
		return nil, fmt.Errorf("armtls: provision certificate: %w", err)
	}
	if err := ensureLeaf(cert); err != nil {
		return nil, err
	}

	if err := usableForHandshake(cert, time.Now()); err != nil {
		return nil, err
	}
	if ttl == 0 {
		ttl = s.effectiveTTL()
	}
	newRotateAt := time.Now().Add(ttl / 2)

	current, installed := s.installProvisionedCertificate(cert, newRotateAt, revision)
	if !installed {
		if current == nil {
			return nil, fmt.Errorf("armtls: certificate changed during provisioning")
		}
		return current, usableForHandshake(current, time.Now())
	}
	s.provisioned.Store(true)
	s.unusableLogged.Store(false)
	s.clearCooldown()

	if s.logger != nil {
		s.logger.Info("armtls: certificate provisioned", "ttl", ttl, "rotateAt", newRotateAt)
	}

	return cert, nil
}

func (s *certState) installProvisionedCertificate(cert *tls.Certificate, rotateAt time.Time, revision uint64) (*tls.Certificate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != revision {
		return s.cert, false
	}
	s.cert = cert
	s.rotateAt = rotateAt
	s.certificateInstalledLocked()
	return cert, true
}

// clearCooldown drops the negative cache. A success is newer evidence about
// the provider than the failure that populated it, so leaving it in place
// could replay a stale error at the next handshake that needs one.
func (s *certState) clearCooldown() {
	s.syncMu.Lock()
	s.cooldownUntil = time.Time{}
	s.cooldownErr = nil
	s.syncMu.Unlock()
}

// ensureLeaf populates cert.Leaf once, at provision time. Every CertProvider
// is required to set it (see the interface's INVARIANT), but a third-party
// implementation that does not would otherwise cost usableForHandshake an
// x509 parse on every single connection.
func ensureLeaf(cert *tls.Certificate) error {
	if cert == nil {
		return fmt.Errorf("armtls: provider returned no certificate")
	}
	if cert.Leaf != nil {
		return nil
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("armtls: provisioned certificate has no leaf")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("armtls: parse provisioned leaf: %w", err)
	}
	cert.Leaf = leaf
	return nil
}

// usableForHandshake reports whether a cached certificate may still be handed
// to a TLS handshake: its leaf must be inside the validity window
// (NotBefore within certutil.LeafValiditySkew, NotAfter with no allowance).
// Leaf is populated by ensureLeaf before anything is cached, so this is a
// field read and two time comparisons — no DER parsing on the handshake path.
func usableForHandshake(cert *tls.Certificate, now time.Time) error {
	if cert.Leaf == nil {
		return fmt.Errorf("armtls: cached certificate has no parsed leaf")
	}
	return certutil.CheckValidity(cert.Leaf, now)
}

// backgroundProvision installs a renewal only while the captured revision is current.
func (s *certState) backgroundProvision(ctx context.Context, spawnProvider CertProvider, revision uint64) {
	defer func() {
		s.mu.Lock()
		if s.rotationCancel != nil {
			s.rotationCancel()
			s.rotationCancel = nil
		}
		s.rotating.Store(false)
		s.notifyRotationEndedLocked()
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, s.effectiveRotationTimeout())
	defer cancel()

	cert, ttl, err := spawnProvider.Provision(ctx)
	if err == nil {
		err = ensureLeaf(cert)
	}
	if err == nil {
		err = usableForHandshake(cert, time.Now())
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("armtls: background certificate rotation failed", "err", err)
		}
		if s.onRotationFail != nil {
			s.onRotationFail()
		}
		s.mu.Lock()
		if s.revision == revision {
			if s.retryBackoff == nil {
				s.retryBackoff = backoff.NewExponentialBackOff()
				s.retryBackoff.InitialInterval = syncProvisionCooldown
				s.retryBackoff.MaxInterval = time.Minute
				s.retryBackoff.Reset()
			}
			s.retryAt = time.Now().Add(s.retryBackoff.NextBackOff())
		}
		s.mu.Unlock()
		return
	}

	if ttl == 0 {
		ttl = s.effectiveTTL()
	}
	rotateAt := time.Now().Add(ttl / 2)
	s.mu.Lock()
	if s.revision != revision {
		s.mu.Unlock()
		return
	}
	s.cert = cert
	s.rotateAt = rotateAt
	s.certificateInstalledLocked()
	s.mu.Unlock()
	s.provisioned.Store(true)
	s.unusableLogged.Store(false)
	s.clearCooldown()

	if s.logger != nil {
		s.logger.Info("armtls: certificate rotated (background)", "ttl", ttl, "rotateAt", rotateAt)
	}
}

// effectiveTTL returns the default TTL, falling back to DefaultCertTTL.
func (s *certState) effectiveTTL() time.Duration {
	if s.defaultTTL > 0 {
		return s.defaultTTL
	}
	return DefaultCertTTL
}

// effectiveRotationTimeout bounds one provisioning round-trip.
func (s *certState) effectiveRotationTimeout() time.Duration {
	if s.rotationTimeout > 0 {
		return s.rotationTimeout
	}
	return defaultRotationTimeout
}

// effectiveSyncCooldown is how long a failed synchronous provision is
// negative-cached.
func (s *certState) effectiveSyncCooldown() time.Duration {
	if s.syncCooldown > 0 {
		return s.syncCooldown
	}
	return syncProvisionCooldown
}

// SwapProvider atomically replaces the certificate provider and triggers
// an immediate re-provisioning. Used for runtime upgrades (e.g., self-signed
// to CDS-issued). The old certificate continues serving until the new one
// is ready — if provisioning fails, the old cert and provider remain active.
func (s *certState) SwapProvider(ctx context.Context, provider CertProvider) error {
	// Provision with the new provider BEFORE swapping. This prevents a
	// readiness gap: if provisioning fails, the old cert and provider
	// remain active (the mesh stays ready and serves traffic).
	cert, ttl, err := provider.Provision(ctx)
	if err == nil {
		err = ensureLeaf(cert)
	}
	if err == nil {
		// Symmetry with getOrProvision, which refuses to serve a cert outside
		// its window: caching one here would install a credential the very
		// next handshake discards, dropping the old cert that still works.
		err = usableForHandshake(cert, time.Now())
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("armtls: certificate provisioning failed", "err", err)
		}
		return fmt.Errorf("armtls: provision certificate: %w", err)
	}

	if ttl == 0 {
		ttl = s.effectiveTTL()
	}
	rotateAt := time.Now().Add(ttl / 2)

	// Swap atomically: old cert served until this lock is released.
	s.mu.Lock()
	s.provider = provider
	s.cert = cert
	s.rotateAt = rotateAt
	s.certificateInstalledLocked()
	s.mu.Unlock()
	s.provisioned.Store(true)
	s.unusableLogged.Store(false)

	// A new provider is a different certificate source; a failure cached
	// against the old one says nothing about it.
	s.clearCooldown()

	if s.logger != nil {
		s.logger.Info("armtls: certificate provisioned", "ttl", ttl, "rotateAt", rotateAt)
	}

	return nil
}

// CertManager provides access to the armTLS certificate lifecycle.
// Use WarmUp to eagerly provision the certificate at startup and CertReady
// to gate readiness probes.
type CertManager struct {
	state *certState
}

// WarmUp eagerly provisions the certificate. Call this at startup (after
// listener bind, before marking ready) to avoid blocking the first handshake.
func (m *CertManager) WarmUp(ctx context.Context) error {
	return m.state.WarmUp(ctx)
}

// CertReady returns true if a certificate has been provisioned at least once.
// It is sticky; gate readiness on [CertManager.CertUsable] as well.
func (m *CertManager) CertReady() bool {
	return m.state.CertReady()
}

// CertUsable returns true if the cached certificate is inside its validity
// window and can therefore still be served. See [certState.CertUsable].
func (m *CertManager) CertUsable() bool {
	return m.state.CertUsable()
}

// CertExpiry returns the NotAfter time of the current certificate, or the zero
// time if no certificate has been provisioned yet.
func (m *CertManager) CertExpiry() time.Time {
	return m.state.CertExpiry()
}

// SetOnRotationFail registers a callback invoked when background rotation fails.
// Useful for incrementing Prometheus counters.
func (m *CertManager) SetOnRotationFail(fn func()) {
	m.state.onRotationFail = fn
}

// SwapProvider replaces the underlying certificate provider at runtime and
// immediately provisions a certificate from the new provider. Use this for
// runtime upgrades (e.g., self-signed to CDS-issued).
func (m *CertManager) SwapProvider(ctx context.Context, provider CertProvider) error {
	return m.state.SwapProvider(ctx, provider)
}

// NewServerTLSConfig creates a tls.Config for an armTLS server. The private
// key is generated in memory and never written to disk. The attestation report
// is obtained lazily on the first TLS handshake and cached until rotation.
//
// If ClientPolicy is set, the server requires client certificates and verifies
// their armTLS attestation (mTLS): a self-issued leaf carrying key-bound
// evidence. ClientCA verifies a chain instead, and the two are exclusive.
//
// If CertProvider is set, it is used for certificate provisioning instead of
// Platform/AttestFunc. When CertProvider is nil, Platform and AttestFunc are
// required and a SelfSignedProvider is created internally.
//
// The returned CertManager can be used to eagerly provision the certificate
// (WarmUp) and check readiness (CertReady).
func NewServerTLSConfig(cfg *ServerConfig) (*tls.Config, *CertManager, error) {
	provider := cfg.CertProvider
	if provider == nil {
		// Fall back to self-signed: require Platform + AttestFunc.
		if cfg.Platform == "" {
			return nil, nil, fmt.Errorf("armtls: Platform is required")
		}
		if _, err := teetypes.ParseFamily(cfg.Platform); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedTEE, err)
		}
		if cfg.AttestFunc == nil {
			return nil, nil, fmt.Errorf("armtls: AttestFunc is required")
		}
		provider = &SelfSignedProvider{
			Platform:   cfg.Platform,
			AttestFunc: cfg.AttestFunc,
			Opts: &CertOptions{
				Subject:  cfg.Subject,
				TTL:      cfg.CertTTL,
				DNSNames: cfg.DNSNames,
			},
		}
	}

	state := &certState{
		provider:        provider,
		logger:          cfg.Logger,
		rotationTimeout: cfg.RotationTimeout,
		defaultTTL:      cfg.CertTTL,
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return state.getOrProvision(hello.Context())
		},
	}
	refuseResumption(tlsCfg)

	// mTLS: require and verify client certificates. A listener authenticates
	// its peers one way.
	if cfg.ClientCA != nil && cfg.ClientPolicy != nil {
		return nil, nil, fmt.Errorf("armtls: ClientCA and ClientPolicy are mutually exclusive (ClientPolicy admits a self-issued armTLS peer, which ClientCA exists to refuse)")
	}
	switch {
	case cfg.ClientCA != nil:
		pool := x509.NewCertPool()
		pool.AddCert(cfg.ClientCA)
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = cfg.ClientAuth
		if tlsCfg.ClientAuth == tls.NoClientCert {
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	case cfg.ClientPolicy != nil:
		tlsCfg.ClientAuth = tls.RequireAnyClientCert
		tlsCfg.VerifyPeerCertificate = verifyPeerCallback(cfg.ClientPolicy, x509.ExtKeyUsageClientAuth)
	}

	return tlsCfg, &CertManager{state: state}, nil
}

// NewClientTLSConfig creates a tls.Config for an armTLS client. Peer
// verification checks key-bound TEE evidence of a self-issued certificate; a
// CDS-issued leaf is verified on the chain path instead
// (NewMeshClientTLSConfig).
//
// If Platform and AttestFunc are set (or CertProvider is set), the client
// presents its own certificate for mutual attestation (mTLS).
//
// The returned CertManager is non-nil only when mTLS is configured. Use it
// for eager provisioning and readiness checks.
//
// Evidence verification requires Policy.AttestationApiURL and fails closed with
// [ErrInvalidReport] when it is empty. For construction-time URL validation,
// use [NewVerifyingHTTPClient].
func NewClientTLSConfig(cfg *ClientConfig) (*tls.Config, *CertManager, error) {
	if cfg == nil {
		cfg = &ClientConfig{}
	}

	// Determine if mTLS is configured.
	hasProvider := cfg.CertProvider != nil
	hasLegacy := cfg.Platform != "" || cfg.AttestFunc != nil

	// Validate mTLS fields: both Platform and AttestFunc, or neither.
	if !hasProvider {
		if (cfg.Platform == "") != (cfg.AttestFunc == nil) {
			return nil, nil, fmt.Errorf("armtls: Platform and AttestFunc must both be set or both unset")
		}
		if cfg.Platform != "" {
			if _, err := teetypes.ParseFamily(cfg.Platform); err != nil {
				return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedTEE, err)
			}
		}
	}

	if cfg.Policy == nil {
		return nil, nil, fmt.Errorf("armtls: Policy is required: the client verifies the server's evidence against it on every handshake")
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Custom peer verification.
	}
	refuseResumption(tlsCfg)

	tlsCfg.VerifyPeerCertificate = verifyPeerCallback(cfg.Policy, x509.ExtKeyUsageServerAuth)

	var mgr *CertManager

	// mTLS: present client certificate.
	if hasProvider || (hasLegacy && cfg.AttestFunc != nil) {
		var provider CertProvider
		if cfg.CertProvider != nil {
			provider = cfg.CertProvider
		} else {
			provider = &SelfSignedProvider{
				Platform:   cfg.Platform,
				AttestFunc: cfg.AttestFunc,
				Opts:       &CertOptions{TTL: cfg.CertTTL},
			}
		}

		state := &certState{
			provider:        provider,
			logger:          cfg.Logger,
			rotationTimeout: cfg.RotationTimeout,
			defaultTTL:      cfg.CertTTL,
		}

		tlsCfg.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return state.getOrProvision(info.Context())
		}

		mgr = &CertManager{state: state}
	}

	return tlsCfg, mgr, nil
}

// verifyPeerCallback returns a VerifyPeerCertificate function that checks the
// peer's armTLS attestation against the given policy, which is required.
// peerPurpose is the TLS purpose the peer's role requires: clientAuth for a
// client, serverAuth for a server.
func verifyPeerCallback(policy *VerifyPolicy, peerPurpose x509.ExtKeyUsage) func([][]byte, [][]*x509.Certificate) error {
	nonce := policy.Nonce
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		cert, err := parsePeerLeaf(rawCerts)
		if err != nil {
			return err
		}
		// The key-type half of this check runs inside VerifyCert; the purpose
		// half runs first so a peer in the wrong role costs no
		// attestation-api round-trip.
		if err := checkPeerPurpose(cert, peerPurpose); err != nil {
			return err
		}
		if _, err := VerifyCert(cert, policy, nonce); err != nil {
			return fmt.Errorf("armtls: peer attestation failed: %w", err)
		}
		return nil
	}
}

// MeshALPN is the application protocol a mesh endpoint negotiates in both
// roles. A peer that offers no other protocol fails the handshake before any
// application byte moves (docs/armtls.md, "The mesh endpoint profile").
const MeshALPN = "c8s-mesh/1"

// MeshConfig configures a mesh endpoint: it presents its pod's CDS-issued leaf
// and authenticates peers on the chain path alone.
type MeshConfig struct {
	// CertProvider provisions the pod's CDS-issued credentials.
	CertProvider CertProvider

	// MeshCA is the mesh CA a peer's leaf must chain to. Required.
	MeshCA *x509.Certificate

	// Logger, when set, receives structured log messages for certificate
	// provisioning, rotation, and errors.
	Logger Logger
}

// NewMeshServerTLSConfig creates the mesh endpoint's server configuration: it
// requires a client certificate and authenticates it as a mesh client.
func NewMeshServerTLSConfig(cfg *MeshConfig) (*tls.Config, *CertManager, error) {
	tlsCfg, mgr, err := newMeshTLSConfig(cfg, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, nil, err
	}
	tlsCfg.ClientAuth = tls.RequireAnyClientCert
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return mgr.state.getOrProvision(hello.Context())
	}
	return tlsCfg, mgr, nil
}

// NewMeshClientTLSConfig creates the mesh endpoint's client configuration: it
// presents the pod's leaf and authenticates the peer as a mesh server.
func NewMeshClientTLSConfig(cfg *MeshConfig) (*tls.Config, *CertManager, error) {
	tlsCfg, mgr, err := newMeshTLSConfig(cfg, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, nil, err
	}
	// The peer's identity is its leaf, never the hostname it answers on, so
	// crypto/tls verification is replaced by the chain callback below.
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return mgr.state.getOrProvision(info.Context())
	}
	return tlsCfg, mgr, nil
}

func newMeshTLSConfig(cfg *MeshConfig, peerPurpose x509.ExtKeyUsage) (*tls.Config, *CertManager, error) {
	if cfg == nil || cfg.CertProvider == nil {
		return nil, nil, fmt.Errorf("armtls: a mesh endpoint requires a CertProvider")
	}
	if cfg.MeshCA == nil {
		return nil, nil, fmt.Errorf("armtls: a mesh endpoint requires its mesh CA")
	}
	tlsCfg := &tls.Config{
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{MeshALPN},
		VerifyPeerCertificate: chainVerifyPeerCallback(cfg.MeshCA, peerPurpose),
		VerifyConnection:      requireMeshALPN,
	}
	refuseResumption(tlsCfg)
	state := &certState{
		provider: cfg.CertProvider,
		logger:   cfg.Logger,
	}
	return tlsCfg, &CertManager{state: state}, nil
}

// chainVerifyPeerCallback returns a VerifyPeerCertificate function that
// authenticates a mesh peer by its CDS-issued chain and the workload instance
// it names. A leaf that does not chain is rejected, never retried against its
// embedded evidence, so a self-signed peer and a peer from another mesh CA
// both fail.
func chainVerifyPeerCallback(meshCA *x509.Certificate, peerPurpose x509.ExtKeyUsage) func([][]byte, [][]*x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(meshCA)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		leaf, intermediates, err := parsePeerChain(rawCerts)
		if err != nil {
			return err
		}
		if err := checkPeerKeyType(leaf); err != nil {
			return err
		}
		if err := checkPeerPurpose(leaf, peerPurpose); err != nil {
			return err
		}
		// Chain validity at the current time: what vouches for a mesh leaf is
		// the CA signature, so there is no evidence window to align a
		// not-before allowance with. Every issuer of the chain must permit the
		// peer's purpose too, not only the leaf checked above.
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{peerPurpose},
			CurrentTime:   time.Now(),
		}); err != nil {
			return fmt.Errorf("armtls: mesh peer chain to a trusted mesh CA: %w", err)
		}
		sandboxID, err := SandboxIDFromCert(leaf)
		if err != nil {
			return fmt.Errorf("armtls: mesh peer sandbox ID: %w", err)
		}
		if sandboxID == "" {
			return fmt.Errorf("armtls: mesh peer leaf carries no sandbox-ID extension")
		}
		return nil
	}
}

// requireMeshALPN refuses a connection that negotiated anything but the mesh
// protocol. crypto/tls completes a handshake with no protocol at all when the
// peer offers no ALPN extension, so the negotiated value is checked here.
func requireMeshALPN(cs tls.ConnectionState) error {
	if cs.NegotiatedProtocol != MeshALPN {
		return fmt.Errorf("armtls: peer negotiated protocol %q, want %q", cs.NegotiatedProtocol, MeshALPN)
	}
	return nil
}

// refuseResumption switches TLS session resumption off in both roles — see
// docs/armtls.md, "No session resumption".
func refuseResumption(cfg *tls.Config) {
	cfg.SessionTicketsDisabled = true
}

// parsePeerLeaf parses the certificate the peer presents for itself.
func parsePeerLeaf(rawCerts [][]byte) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("armtls: no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("armtls: parse peer cert: %w", err)
	}
	return leaf, nil
}

// parsePeerChain splits the peer's presented certificates into its leaf and
// the intermediates it offered. An unparsable intermediate is a failure, not a
// dropped element.
func parsePeerChain(rawCerts [][]byte) (*x509.Certificate, *x509.CertPool, error) {
	leaf, err := parsePeerLeaf(rawCerts)
	if err != nil {
		return nil, nil, err
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		intermediate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("armtls: parse peer intermediate: %w", err)
		}
		intermediates.AddCert(intermediate)
	}
	return leaf, intermediates, nil
}

// checkPeerPurpose refuses a certificate that does not carry the TLS purpose
// its holder's role requires.
func checkPeerPurpose(cert *x509.Certificate, peerPurpose x509.ExtKeyUsage) error {
	if permitsPurpose(cert, peerPurpose) {
		return nil
	}
	purpose := "serverAuth"
	if peerPurpose == x509.ExtKeyUsageClientAuth {
		purpose = "clientAuth"
	}
	return fmt.Errorf("armtls: peer certificate does not permit %s", purpose)
}

func permitsPurpose(cert *x509.Certificate, peerPurpose x509.ExtKeyUsage) bool {
	return slices.Contains(cert.ExtKeyUsage, peerPurpose)
}
