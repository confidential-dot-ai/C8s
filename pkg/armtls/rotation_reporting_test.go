package armtls

import (
	"context"
	"crypto/tls"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// issuingProvider hands out a fresh certificate and records every call, so a
// test can assert a rotation was (or was not) started.
type issuingProvider struct {
	calls atomic.Int32
	cert  *tls.Certificate
	ttl   time.Duration
}

func (p *issuingProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	p.calls.Add(1)
	return p.cert, p.ttl, nil
}

func infoContains(l *countingLogger, substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, msg := range l.infos {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// A rotation that fails is the start of an outage: it has to reach the log and
// the failure callback, and it must arm a retry instead of hot-looping.
func TestBackgroundProvisionReportsFailure(t *testing.T) {
	logger := &countingLogger{}
	failures := 0
	state := &certState{
		provider:       errProvider{},
		logger:         logger,
		onRotationFail: func() { failures++ },
	}

	state.backgroundProvision(context.Background(), errProvider{}, state.revision)

	if got := logger.countWarns("background certificate rotation failed"); got != 1 {
		t.Fatalf("warnings = %d, want the failure reported once", got)
	}
	if failures != 1 {
		t.Fatalf("onRotationFail calls = %d, want 1", failures)
	}
	if state.retryAt.IsZero() {
		t.Fatal("a failed rotation armed no retry")
	}
	if state.CertReady() {
		t.Fatal("a failed rotation reported the certificate as ready")
	}
}

// The successful counterpart: the new certificate is installed, readiness is
// set, and the rotation is reported with the window it bought.
func TestBackgroundProvisionReportsRotation(t *testing.T) {
	logger := &countingLogger{}
	fresh := generateSimpleCert(t)
	state := &certState{
		provider: &mockProvider{cert: fresh, ttl: time.Hour},
		logger:   logger,
	}

	state.backgroundProvision(context.Background(), state.provider, state.revision)

	if state.cert != fresh {
		t.Fatal("a successful rotation did not install the new certificate")
	}
	if !state.CertReady() {
		t.Fatal("a successful rotation left the certificate unready")
	}
	if !infoContains(logger, "certificate rotated (background)") {
		t.Fatal("a successful rotation was not reported")
	}
}

// A certificate that expires before its scheduled rotation must be rotated at
// expiry, not at the schedule: otherwise handshakes fail closed in the gap.
func TestRotateIfDueClampsDeadlineToLeafExpiry(t *testing.T) {
	provider := &issuingProvider{
		cert: generateSimpleCert(t),
		ttl:  time.Hour,
	}
	state := &certState{provider: provider}
	state.cert = simpleCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Minute))
	state.rotateAt = time.Now().Add(time.Hour)

	state.rotateIfDue(context.Background())

	if provider.calls.Load() != 1 {
		t.Fatalf("provision calls = %d, want the expired certificate rotated", provider.calls.Load())
	}
	if state.cert != provider.cert {
		t.Fatal("the expired certificate was not replaced")
	}
}

// With the rotation loop running, a handshake-time rotation request is the
// loop's job. Starting a second one would mean two concurrent provisioning
// round-trips against the same certificate source.
func TestRequestRotationDefersToTheRotationLoop(t *testing.T) {
	provider := &issuingProvider{
		cert: generateSimpleCert(t),
		ttl:  time.Hour,
	}
	state := &certState{
		provider:      provider,
		rotationEnded: make(chan struct{}, 1),
	}

	state.requestRotation(provider, state.revision)

	if provider.calls.Load() != 0 {
		t.Fatalf("provision calls = %d, want the loop left to rotate", provider.calls.Load())
	}
}

// A swap that fails must keep the working certificate and provider: the pod
// stays ready on the credential it already has, and the failure is reported.
func TestSwapProviderReportsFailureAndKeepsCertificate(t *testing.T) {
	logger := &countingLogger{}
	serving := generateSimpleCert(t)
	old := &mockProvider{cert: serving, ttl: time.Hour}
	state := &certState{
		provider:   old,
		logger:     logger,
		defaultTTL: time.Hour,
	}
	state.cert = serving

	err := state.SwapProvider(context.Background(), errProvider{})
	if err == nil {
		t.Fatal("SwapProvider installed a provider that cannot provision")
	}
	if state.cert != serving {
		t.Fatal("a failed swap dropped the certificate still serving traffic")
	}
	if state.provider != old {
		t.Fatal("a failed swap installed the new provider anyway")
	}
	if got := logger.countWarns("certificate provisioning failed"); got != 1 {
		t.Fatalf("warnings = %d, want the failure reported once", got)
	}
}

// The successful counterpart: the new provider and its certificate take over
// and the swap is reported.
func TestSwapProviderReportsSuccess(t *testing.T) {
	logger := &countingLogger{}
	state := &certState{
		provider:   &mockProvider{cert: generateSimpleCert(t), ttl: time.Hour},
		logger:     logger,
		defaultTTL: time.Hour,
	}
	replacement := generateSimpleCert(t)

	err := state.SwapProvider(context.Background(), &mockProvider{cert: replacement, ttl: time.Hour})
	if err != nil {
		t.Fatalf("SwapProvider: %v", err)
	}
	if state.cert != replacement {
		t.Fatal("the swapped-in certificate is not the one being served")
	}
	if !infoContains(logger, "certificate provisioned") {
		t.Fatal("a successful swap was not reported")
	}
}
