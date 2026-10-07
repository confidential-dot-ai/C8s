package armtls

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatedProvider is a certificate source a test can hold open: the first
// Provision blocks until release is closed, which is what lets a test observe
// what the handshake path does while an attempt is still running.
type gatedProvider struct {
	calls   atomic.Int32
	entered chan struct{} // closed on the first entry
	release chan struct{} // closed to let Provision return
	once    sync.Once
	cert    *tls.Certificate
	ttl     time.Duration
	err     error
}

func newGatedProvider(cert *tls.Certificate, ttl time.Duration, err error) *gatedProvider {
	return &gatedProvider{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		cert:    cert,
		ttl:     ttl,
		err:     err,
	}
}

func (p *gatedProvider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	p.calls.Add(1)
	p.once.Do(func() { close(p.entered) })
	select {
	case <-p.release:
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	return p.cert, p.ttl, p.err
}

// countingLogger records the messages a certState emits.
type countingLogger struct {
	mu    sync.Mutex
	warns []string
	infos []string
}

func (l *countingLogger) Info(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, msg)
}

func (l *countingLogger) Warn(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}

func (l *countingLogger) countWarns(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, w := range l.warns {
		if strings.Contains(w, substr) {
			n++
		}
	}
	return n
}

// expiredState is the shape of the outage this file is about: a cached
// certificate past NotAfter, so every handshake takes the fail-closed path.
func expiredState(t *testing.T, provider CertProvider) *certState {
	t.Helper()
	s := &certState{provider: provider}
	s.cert = simpleCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	s.rotateAt = time.Now().Add(time.Hour) // expiry is a hard stop on its own
	s.provisioned.Store(true)
	return s
}

// Concurrent handshakes against an expired cache and a down provider must
// produce ONE provisioning attempt, not one per connection: the sync path is
// the fail-closed path, so without single-flighting a certificate source that
// is already failing gets N serialized retries with no backoff.
func TestSyncProvisionSingleFlightsConcurrentHandshakes(t *testing.T) {
	provisionErr := errors.New("certificate source down")
	provider := newGatedProvider(nil, 0, provisionErr)
	s := expiredState(t, provider)
	// Effectively no negative cache, so a straggler that did NOT join the
	// in-flight attempt would start a second one and fail this test.
	s.syncCooldown = time.Nanosecond

	const handshakes = 20
	errs := make([]error, handshakes)
	var wg sync.WaitGroup
	wg.Add(handshakes)
	for i := range handshakes {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = s.getOrProvision(context.Background())
		}(i)
	}

	<-provider.entered
	// Give the other handshakes time to pile up behind the attempt.
	time.Sleep(50 * time.Millisecond)
	close(provider.release)
	wg.Wait()

	if got := provider.calls.Load(); got != 1 {
		t.Fatalf("provider called %d times for %d concurrent handshakes, want 1", got, handshakes)
	}
	for i, err := range errs {
		if !errors.Is(err, provisionErr) {
			t.Fatalf("handshake %d: err = %v, want the provisioning error", i, err)
		}
	}
}

// A failed synchronous provision is replayed from a negative cache for the
// cooldown, so a provider outage costs one request per cooldown rather than
// one per connection. The cooldown must also expire.
func TestSyncProvisionNegativeCachesFailure(t *testing.T) {
	provisionErr := errors.New("certificate source down")
	s := expiredState(t, &erroringProvider{err: provisionErr})
	s.syncCooldown = 250 * time.Millisecond

	var calls atomic.Int32
	counting := &countingProvider{calls: &calls, err: provisionErr}
	s.mu.Lock()
	s.provider = counting
	s.mu.Unlock()

	for i := range 5 {
		if _, err := s.getOrProvision(context.Background()); !errors.Is(err, provisionErr) {
			t.Fatalf("call %d: err = %v, want the provisioning error", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider called %d times during the cooldown, want 1", got)
	}

	time.Sleep(300 * time.Millisecond)
	if _, err := s.getOrProvision(context.Background()); !errors.Is(err, provisionErr) {
		t.Fatalf("after cooldown: err = %v, want the provisioning error", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("provider called %d times after the cooldown expired, want 2", got)
	}
}

type countingProvider struct {
	calls *atomic.Int32
	err   error
}

func (p *countingProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	p.calls.Add(1)
	return nil, 0, p.err
}

// The synchronous path runs under GetCertificate, whose context comes from
// tls.NewListener and carries no deadline: a wedged provider must be cut off
// by the rotation timeout rather than parking the handshake forever.
func TestSyncProvisionIsTimeBounded(t *testing.T) {
	// Never released — only ctx expiry can end this Provision.
	provider := newGatedProvider(nil, 0, nil)
	s := expiredState(t, provider)
	s.rotationTimeout = 100 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := s.getOrProvision(context.Background())
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want the bounded-provision deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("synchronous provisioning was not bounded by the rotation timeout")
	}
}

// The "cached certificate is outside its validity window" warning is on the
// handshake path: one line per connection would flood exactly during the
// outage whose logs matter. Log once per entry into that state.
func TestSyncProvisionLogsUnusableCacheOncePerTransition(t *testing.T) {
	logger := &countingLogger{}
	provisionErr := errors.New("certificate source down")
	s := expiredState(t, &erroringProvider{err: provisionErr})
	s.logger = logger
	s.syncCooldown = time.Nanosecond

	const msg = "outside its validity window"
	for range 5 {
		if _, err := s.getOrProvision(context.Background()); err == nil {
			t.Fatal("expected the provisioning error")
		}
	}
	if got := logger.countWarns(msg); got != 1 {
		t.Fatalf("logged the unusable-cache warning %d times over 5 handshakes, want 1", got)
	}

	// Provider recovers: the state is left, so the next entry logs again.
	s.mu.Lock()
	s.provider = &mockProvider{cert: generateSimpleCert(t), ttl: time.Hour}
	s.mu.Unlock()
	if _, err := s.getOrProvision(context.Background()); err != nil {
		t.Fatalf("recovered provider: %v", err)
	}

	s.mu.Lock()
	s.cert = simpleCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	s.provider = &erroringProvider{err: provisionErr}
	s.mu.Unlock()
	if _, err := s.getOrProvision(context.Background()); err == nil {
		t.Fatal("expected the provisioning error")
	}
	if got := logger.countWarns(msg); got != 2 {
		t.Fatalf("logged the unusable-cache warning %d times across two transitions, want 2", got)
	}
}

// A background rotation in flight when the cert crosses NotAfter runs
// alongside the synchronous provision and can finish after it. It must not
// overwrite the newer certificate with its own older one.
func TestBackgroundProvisionDropsResultWhenNewerCertLanded(t *testing.T) {
	stale := generateSimpleCert(t)
	provider := newGatedProvider(stale, time.Hour, nil)
	s := &certState{provider: provider, defaultTTL: time.Hour}
	s.cert = generateSimpleCert(t)
	spawnRotateAt := time.Now().Add(-time.Minute) // rotation was due
	s.rotateAt = spawnRotateAt
	s.provisioned.Store(true)

	s.rotating.Store(true)
	rotationDone := make(chan struct{})
	go func() {
		defer close(rotationDone)
		s.backgroundProvision(context.Background(), provider, 0)
	}()

	<-provider.entered
	// The synchronous path lands a newer certificate while rotation works.
	newer := generateSimpleCert(t)
	s.mu.Lock()
	s.cert = newer
	s.rotateAt = time.Now().Add(30 * time.Minute)
	s.revision++
	s.mu.Unlock()

	close(provider.release)
	<-rotationDone

	s.mu.RLock()
	got := s.cert
	s.mu.RUnlock()
	if got != newer {
		t.Fatal("background rotation overwrote a newer certificate with its own older one")
	}
}

// SwapProvider must refuse a certificate getOrProvision would then refuse to
// serve: caching it would drop an old certificate that still works in favour
// of one no handshake can use.
func TestSwapProviderRejectsCertOutsideValidityWindow(t *testing.T) {
	good := generateSimpleCert(t)
	oldProvider := &mockProvider{cert: good, ttl: time.Hour}
	s := &certState{provider: oldProvider, defaultTTL: time.Hour}
	if _, err := s.getOrProvision(context.Background()); err != nil {
		t.Fatal(err)
	}

	expired := simpleCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	newProvider := &mockProvider{cert: expired, ttl: time.Hour}
	if err := s.SwapProvider(context.Background(), newProvider); err == nil {
		t.Fatal("SwapProvider cached a certificate outside its validity window")
	}

	s.mu.RLock()
	gotCert, gotProvider := s.cert, s.provider
	s.mu.RUnlock()
	if gotCert != good {
		t.Error("the working certificate was replaced by the rejected one")
	}
	if gotProvider != CertProvider(oldProvider) {
		t.Error("the provider was swapped despite the failure")
	}
}

// leaflessProvider models a third-party CertProvider that does not honour the
// interface's Leaf invariant.
type leaflessProvider struct{ cert *tls.Certificate }

func (p *leaflessProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	return &tls.Certificate{Certificate: p.cert.Certificate, PrivateKey: p.cert.PrivateKey}, time.Hour, nil
}

// The leaf is parsed once at provision time, not on every handshake: a
// provider that leaves Leaf nil must not cost an x509 parse per connection.
func TestProvisionPopulatesLeafOnce(t *testing.T) {
	s := &certState{provider: &leaflessProvider{cert: generateSimpleCert(t)}, defaultTTL: time.Hour}
	cert, err := s.getOrProvision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		t.Fatal("Leaf was not populated at provision time")
	}
	// usableForHandshake can then be a field read, and says so by refusing a
	// certificate that has no parsed leaf.
	if err := usableForHandshake(&tls.Certificate{}, time.Now()); err == nil {
		t.Fatal("usableForHandshake accepted a certificate with no parsed leaf")
	}
}

// CertReady is sticky; CertUsable is what says a handshake would succeed. The
// two must disagree exactly in the terminal state /ready has to catch.
func TestCertUsableTracksTheValidityWindow(t *testing.T) {
	s := &certState{provider: &mockProvider{cert: generateSimpleCert(t), ttl: time.Hour}, defaultTTL: time.Hour}
	if s.CertUsable() {
		t.Error("CertUsable = true before any certificate was provisioned")
	}
	if _, err := s.getOrProvision(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.CertReady() || !s.CertUsable() {
		t.Fatalf("after provisioning: CertReady = %v, CertUsable = %v, want both true", s.CertReady(), s.CertUsable())
	}

	s.mu.Lock()
	s.cert = simpleCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	s.mu.Unlock()
	if !s.CertReady() {
		t.Error("CertReady must keep its 'provisioned at least once' meaning")
	}
	if s.CertUsable() {
		t.Error("CertUsable = true for a certificate past NotAfter")
	}
}

// A success is newer evidence about the provider than the failure that
// populated the negative cache, so it must drop it: otherwise the next
// handshake that needs a synchronous provision replays a stale error.
func TestSyncProvisionSuccessClearsTheNegativeCache(t *testing.T) {
	provisionErr := errors.New("certificate source down")
	s := expiredState(t, &erroringProvider{err: provisionErr})
	s.syncCooldown = time.Hour

	if _, err := s.getOrProvision(context.Background()); !errors.Is(err, provisionErr) {
		t.Fatalf("err = %v, want the provisioning error", err)
	}

	// A background rotation lands a certificate while the cooldown is still
	// running; the cache it left behind must not outlive it.
	fresh := generateSimpleCert(t)
	working := &mockProvider{cert: fresh, ttl: time.Hour}
	s.mu.Lock()
	s.provider = working
	revision := s.revision
	s.mu.Unlock()
	s.rotating.Store(true)
	s.backgroundProvision(context.Background(), working, revision)

	// Back into the fail-closed path with a provider that works.
	s.mu.Lock()
	s.cert = simpleCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	s.mu.Unlock()

	got, err := s.getOrProvision(context.Background())
	if err != nil {
		t.Fatalf("a stale negative cache outlived a successful provision: %v", err)
	}
	if got != fresh {
		t.Fatal("expected the freshly provisioned certificate")
	}
}
