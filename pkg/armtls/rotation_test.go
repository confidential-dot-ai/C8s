package armtls

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type rotationProviderFunc func(context.Context) (*tls.Certificate, time.Duration, error)

func (f rotationProviderFunc) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	return f(ctx)
}

func TestRotationReplacesCertificateWithoutParsedLeaf(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fresh := generateSimpleCert(t)
		unparsed := *fresh
		unparsed.Leaf = nil
		m := &CertManager{state: &certState{
			cert:     &unparsed,
			rotateAt: time.Now().Add(time.Minute),
			provider: &mockProvider{cert: fresh, ttl: time.Hour},
		}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go m.RunRotation(ctx)
		synctest.Wait()
		if m.CertUsable() {
			t.Fatal("certificate without a parsed leaf became usable before renewal")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if !m.CertUsable() || !m.CertExpiry().Equal(fresh.Leaf.NotAfter) {
			t.Fatal("worker did not replace the certificate without a parsed leaf")
		}
	})
}

func TestRotationRecoversAfterExpiryWithoutHandshakes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fail atomic.Bool
		var calls atomic.Int32
		provider := rotationProviderFunc(func(context.Context) (*tls.Certificate, time.Duration, error) {
			calls.Add(1)
			if fail.Load() {
				return nil, 0, errors.New("provider unavailable")
			}
			return simpleCertWithWindow(t, time.Now().Add(-time.Second), time.Now().Add(4*time.Minute)), 4 * time.Minute, nil
		})
		m := &CertManager{state: &certState{provider: &provider}}
		if err := m.WarmUp(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go m.RunRotation(ctx)
		synctest.Wait()
		fail.Store(true)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		m.state.mu.RLock()
		firstRetry := time.Until(m.state.retryAt)
		m.state.mu.RUnlock()
		if firstRetry < 2500*time.Millisecond || firstRetry > 7500*time.Millisecond {
			t.Fatalf("first retry = %v, want 5s with 50%% jitter", firstRetry)
		}
		time.Sleep(2*time.Minute + time.Second)
		synctest.Wait()
		if m.CertUsable() {
			t.Fatal("expired certificate remains usable")
		}
		if calls.Load() < 2 {
			t.Fatal("idle manager did not attempt renewal")
		}
		failedCalls := calls.Load()
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if calls.Load() <= failedCalls || calls.Load() > 20 {
			t.Fatalf("renewal attempts = %d, want bounded retries past expiry", calls.Load())
		}
		fail.Store(false)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if !m.CertUsable() {
			t.Fatal("idle manager did not recover after provider recovery")
		}
	})
}

func TestRotationObservesShorterLifetimeAfterProviderSwap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := &mockProvider{cert: simpleCertWithWindow(t, time.Now().Add(-time.Second), time.Now().Add(time.Hour)), ttl: time.Hour}
		m := &CertManager{state: &certState{provider: old}}
		if err := m.WarmUp(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go m.RunRotation(ctx)
		synctest.Wait()
		var calls atomic.Int32
		replacement := rotationProviderFunc(func(context.Context) (*tls.Certificate, time.Duration, error) {
			calls.Add(1)
			return simpleCertWithWindow(t, time.Now().Add(-time.Second), time.Now().Add(4*time.Minute)), 4 * time.Minute, nil
		})
		if err := m.SwapProvider(ctx, &replacement); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if calls.Load() < 3 || !m.CertUsable() {
			t.Fatalf("shorter-lived provider: calls=%d, usable=%v", calls.Load(), m.CertUsable())
		}
	})
}

func TestRotationCancelsProvisioning(t *testing.T) {
	for _, source := range []string{"worker", "handshake before worker"} {
		t.Run(source, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := newGatedProvider(nil, 0, nil)
				m := &CertManager{state: &certState{provider: provider}}
				if source == "handshake before worker" {
					m.state.cert = generateSimpleCert(t)
					if _, err := m.state.getOrProvision(context.Background()); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					m.RunRotation(ctx)
				}()
				synctest.Wait()
				if provider.calls.Load() != 1 {
					t.Fatal("expected exactly one in-flight provision")
				}
				cancel()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("worker failed to cancel in-flight provisioning")
				}
				if m.state.rotating.Load() {
					t.Fatal("provisioning outlived worker shutdown")
				}
			})
		})
	}
}

func TestSynchronousProvisionCannotOverwriteProviderSwap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newGatedProvider(generateSimpleCert(t), time.Hour, nil)
		s := expiredState(t, old)
		result := make(chan *tls.Certificate, 1)
		go func() {
			cert, _ := s.getOrProvision(context.Background())
			result <- cert
		}()
		synctest.Wait()
		fresh := generateSimpleCert(t)
		if err := s.SwapProvider(context.Background(), &mockProvider{cert: fresh, ttl: time.Hour}); err != nil {
			t.Fatal(err)
		}
		close(old.release)
		synctest.Wait()
		if got := <-result; got != fresh {
			t.Fatal("handshake returned the stale provider certificate")
		}
		if s.cert != fresh {
			t.Fatal("stale provision overwrote provider upgrade")
		}
	})
}

func TestPollingExpiryBeforeNextTickFailsClosedAndHandshakeRecovers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		expiry := time.Now().Add(30 * time.Second)
		short := simpleCertWithWindow(t, time.Now().Add(-time.Second), expiry)
		fresh := generateSimpleCert(t)
		m := &CertManager{state: &certState{
			cert:     short,
			rotateAt: time.Now().Add(time.Until(short.Leaf.NotAfter) / 2),
			provider: &mockProvider{cert: fresh, ttl: time.Hour},
		}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go m.RunRotation(ctx)
		synctest.Wait()
		time.Sleep(45 * time.Second)
		synctest.Wait()
		if m.CertUsable() {
			t.Fatal("certificate expired between polls remained usable")
		}
		got, err := m.state.getOrProvision(ctx)
		if err != nil || got != fresh {
			t.Fatalf("expired handshake recovery: certificate=%p, err=%v", got, err)
		}
		if !m.CertUsable() {
			t.Fatal("fresh certificate did not restore usability")
		}
	})
}

func TestRotationPollHonorsBackoffAcrossTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		fresh := generateSimpleCert(t)
		provider := rotationProviderFunc(func(context.Context) (*tls.Certificate, time.Duration, error) {
			calls.Add(1)
			return fresh, time.Hour, nil
		})
		m := &CertManager{state: &certState{
			provider: &provider,
			retryAt:  time.Now().Add(90 * time.Second),
		}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go m.RunRotation(ctx)
		synctest.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls.Load() != 0 {
			t.Fatal("minute tick retried before backoff elapsed")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls.Load() != 1 || !m.CertUsable() {
			t.Fatal("next tick did not provision after backoff elapsed")
		}
	})
}
