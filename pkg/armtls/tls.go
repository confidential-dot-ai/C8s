package armtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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

	// CACert enables mesh-CA verification with embedded-evidence fallback.
	CACert []*x509.Certificate

	// DynamicCACert, when true, enables dual-mode verification with an
	// initially empty CA pool. CA certs are populated later via
	// CertManager.UpdateCACerts. Until then, peers require embedded evidence.
	// Use this when CA certs are fetched at runtime (e.g., from CDS /ca).
	DynamicCACert bool

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

	// ClientCAs, when set, has crypto/tls verify a presented client
	// certificate against these roots, with no embedded-evidence fallback: a leaf that does
	// not chain is rejected in the handshake. Mutually exclusive with
	// ClientPolicy, whose dual verifier accepts a self-signed armTLS peer as a
	// fallback — for a handler that reads a CDS-stamped field out of the leaf
	// (the sandbox ID), that fallback would let any attested TEE assert an
	// arbitrary value.
	//
	// Pair it with ClientAuth to choose whether a certificate is required.
	// Because the chain is verified here, r.TLS.VerifiedChains is populated and
	// a handler need not re-verify.
	ClientCAs []*x509.Certificate

	// ClientAuth selects how a client certificate is demanded when ClientCAs is
	// set; it defaults to tls.VerifyClientCertIfGiven, which lets a certless
	// caller still reach the routes that need no identity while holding any
	// certificate that IS presented to the ClientCAs roots. Ignored unless
	// ClientCAs is set.
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

// ClientConfig configures an armTLS client that verifies embedded evidence
// or a certificate chain to a configured mesh CA.
type ClientConfig struct {
	// Policy defines acceptable attestation claims for the server.
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

	// CACert enables mesh-CA verification with embedded-evidence fallback.
	CACert []*x509.Certificate

	// DynamicCACert, when true, enables dual-mode verification with an
	// initially empty CA pool. CA certs are populated later via
	// CertManager.UpdateCACerts.
	DynamicCACert bool

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

// sharedCACerts holds a dynamically-updatable list of CA certificates
// for dual-mode (CA chain + embedded evidence) peer verification.
type sharedCACerts struct {
	pool  atomic.Pointer[x509.CertPool]
	certs atomic.Pointer[[]*x509.Certificate]
}

func newSharedCACerts(certs []*x509.Certificate) *sharedCACerts {
	s := &sharedCACerts{}
	s.update(certs)
	return s
}

func (s *sharedCACerts) update(certs []*x509.Certificate) {
	pool := x509.NewCertPool()
	for _, ca := range certs {
		pool.AddCert(ca)
	}
	s.pool.Store(pool)
	s.certs.Store(&certs)
}

func (s *sharedCACerts) getPool() *x509.CertPool {
	return s.pool.Load()
}

// CertManager provides access to the armTLS certificate lifecycle.
// Use WarmUp to eagerly provision the certificate at startup and CertReady
// to gate readiness probes.
type CertManager struct {
	state    *certState
	sharedCA *sharedCACerts // non-nil when dual-mode verification is active
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

// UpdateCACerts dynamically updates the CA certificates a peer is verified
// against: the dual-mode trust anchors of a mesh endpoint polling the CDS /ca
// endpoint, and the ClientCAs pool of a listener whose CA renewed its
// certificate.
func (m *CertManager) UpdateCACerts(certs []*x509.Certificate) {
	if m.sharedCA != nil {
		m.sharedCA.update(certs)
	}
}

// NewServerTLSConfig creates a tls.Config for an armTLS server. The private
// key is generated in memory and never written to disk. The attestation report
// is obtained lazily on the first TLS handshake and cached until rotation.
//
// If ClientPolicy is set, the server requires client certificates and verifies
// their armTLS attestation (mTLS). If CACert is also set, the server accepts
// peers with either verified embedded evidence or a certificate chain to the CA.
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

	// mTLS: require and verify client certificates.
	var sharedCA *sharedCACerts
	switch {
	case len(cfg.ClientCAs) > 0:
		if cfg.ClientPolicy != nil {
			return nil, nil, fmt.Errorf("armtls: ClientCAs and ClientPolicy are mutually exclusive (ClientPolicy admits a self-signed armTLS peer, which ClientCAs exists to refuse)")
		}
		sharedCA = newSharedCACerts(cfg.ClientCAs)
		tlsCfg.ClientCAs = sharedCA.getPool()
		tlsCfg.ClientAuth = cfg.ClientAuth
		if tlsCfg.ClientAuth == tls.NoClientCert {
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
		tlsCfg.GetConfigForClient = clientCAsPerHandshake(tlsCfg, sharedCA)
	case cfg.ClientPolicy != nil:
		tlsCfg.ClientAuth = tls.RequireAnyClientCert
		if len(cfg.CACert) > 0 || cfg.DynamicCACert {
			sharedCA = newSharedCACerts(cfg.CACert) // empty slice is fine — falls through to embedded-evidence verification
			tlsCfg.VerifyPeerCertificate = dualVerifyPeerCallback(cfg.ClientPolicy, sharedCA)
		} else {
			tlsCfg.VerifyPeerCertificate = verifyPeerCallback(cfg.ClientPolicy)
		}
	}

	mgr := &CertManager{state: state, sharedCA: sharedCA}
	return tlsCfg, mgr, nil
}

// clientCAsPerHandshake reads the client CA pool once per connection, so a
// pool replaced through [CertManager.UpdateCACerts] — the CA that renewed its
// certificate — verifies the next client certificate presented.
func clientCAsPerHandshake(base *tls.Config, shared *sharedCACerts) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(*tls.ClientHelloInfo) (*tls.Config, error) {
		current := base.Clone()
		current.ClientCAs = shared.getPool()
		return current, nil
	}
}

// NewClientTLSConfig creates a tls.Config for an armTLS client. Peer verification
// checks key-bound TEE evidence or a chain to the configured mesh CA.
// Policy.RequireCAEvidence also requires evidence verification for CA-signed
// certificates.
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

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Custom peer verification.
	}

	// Peer verification: dual-mode if CACert is set (or DynamicCACert for runtime population).
	var clientSharedCA *sharedCACerts
	if len(cfg.CACert) > 0 || cfg.DynamicCACert {
		clientSharedCA = newSharedCACerts(cfg.CACert) // empty slice is fine — falls through to embedded-evidence verification
		tlsCfg.VerifyPeerCertificate = dualVerifyPeerCallback(cfg.Policy, clientSharedCA)
	} else {
		tlsCfg.VerifyPeerCertificate = verifyPeerCallback(cfg.Policy)
	}

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

		mgr = &CertManager{state: state, sharedCA: clientSharedCA}
	}

	return tlsCfg, mgr, nil
}

// verifyPeerCallback returns a VerifyPeerCertificate function that checks
// the peer's armTLS attestation against the given policy.
func verifyPeerCallback(policy *VerifyPolicy) func([][]byte, [][]*x509.Certificate) error {
	// Extract nonce from policy for use in verification.
	var nonce []byte
	if policy != nil {
		nonce = policy.Nonce
	}

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("armtls: no peer certificate")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("armtls: parse peer cert: %w", err)
		}

		_, err = VerifyCert(cert, policy, nonce)
		if err != nil {
			return fmt.Errorf("armtls: peer attestation failed: %w", err)
		}
		return nil
	}
}

// dualVerifyPeerCallback returns a VerifyPeerCertificate function that accepts
// peers with either verified embedded evidence or a certificate chain to any
// of the given CAs. This enables rolling upgrades where some nodes have
// CA-signed certificates and others still use self-signed armTLS. The
// multi-cert pool also supports CA rotation: include both old and new CA
// during the transition window.
func dualVerifyPeerCallback(policy *VerifyPolicy, shared *sharedCACerts) func([][]byte, [][]*x509.Certificate) error {
	var nonce []byte
	if policy != nil {
		nonce = policy.Nonce
	}

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("armtls: no peer certificate")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("armtls: parse peer cert: %w", err)
		}

		// Try X.509 chain verification first (fast path — no AMD KDS).
		// Read the CA pool atomically so UpdateCACerts is safe.
		caPool := shared.getPool()
		intermediates := x509.NewCertPool()
		for _, rawCert := range rawCerts[1:] {
			if ic, err := x509.ParseCertificate(rawCert); err == nil {
				intermediates.AddCert(ic)
			}
		}
		// Both branches must share one validity window. x509.Verify grants no
		// NotBefore skew while certutil.CheckValidity (the embedded-evidence branch,
		// through VerifyCert) grants certutil.LeafValiditySkew, so without
		// CurrentTime a CA-signed leaf minted a couple of minutes into our
		// future fails the chain here and silently falls through to embedded-evidence verification —
		// where the sandbox and workload pins below are not enforced at all.
		// Shifting CurrentTime closes that divergence; the leaf's own NotAfter
		// is then re-checked at the true now, so the shift buys nothing at the
		// expiry end.
		now := time.Now()
		_, chainErr := cert.Verify(x509.VerifyOptions{
			Roots:         caPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			CurrentTime:   now.Add(certutil.LeafValiditySkew),
		})
		if chainErr == nil {
			chainErr = certutil.CheckValidity(cert, now)
		}
		if chainErr == nil {
			// The chain is verified here and only here, so this is the one place
			// a sandbox-ID or workload pin can be enforced: CDS's signature over
			// the leaf is what authenticates both. No-ops when no pin is set.
			if policy != nil {
				if err := CheckSandboxPin(cert, policy.SandboxID); err != nil {
					return fmt.Errorf("armtls: CA-signed peer failed the sandbox-ID pin: %w", err)
				}
				if err := CheckWorkloadPin(cert, policy.WorkloadName); err != nil {
					return fmt.Errorf("armtls: CA-signed peer failed the workload pin: %w", err)
				}
			}
			// A valid CA chain authenticates the issuer; what else must hold
			// depends on the trust mode (see VerifyPolicy.RequireCAEvidence).
			if policy != nil && policy.RequireCAEvidence {
				// Production mode: the CA chain alone is not sufficient. The leaf
				// must carry re-verifiable armTLS evidence (issuer.SignCSR copies
				// the requester's nonce-free .1.1 extension onto the leaf), which
				// we re-verify here so a CA compromise or wrong issuance policy is
				// caught at the peer instead of trusted from the chain. VerifyCert
				// checks the hardware evidence, launch measurement, and the key
				// binding via the attestation-api. The embedded evidence is
				// nonce-free by construction, so verify with a nil nonce; TLS 1.3
				// supplies connection liveness. A leaf with no (or stale/forged)
				// evidence fails closed. The sandbox and workload pins are already
				// enforced above and are not evidence-bound, so clear them for
				// this call.
				evidencePolicy := *policy
				evidencePolicy.SandboxID = ""
				evidencePolicy.WorkloadName = ""
				if _, err := VerifyCert(cert, &evidencePolicy, nil); err != nil {
					return fmt.Errorf("armtls: CA-signed peer failed embedded-evidence re-verification: %w", err)
				}
			}
			return nil
		}

		// Fall back to embedded-evidence verification. A sandbox-ID pin cannot
		// be satisfied here — a self-signed leaf's extension is chosen by
		// whoever minted it — and VerifyCert fails closed on one.
		_, err = VerifyCert(cert, policy, nonce)
		if err != nil {
			return fmt.Errorf("armtls: peer verification failed (CA chain: %v; armTLS: %w)", chainErr, err)
		}
		return nil
	}
}
