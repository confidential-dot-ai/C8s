package acme

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// newStateManager is newTestManager with an encrypted state volume that is
// already mounted.
func newStateManager(t *testing.T, ca *testCA) (*manager, *fakeACME) {
	t.Helper()
	mgr := newTestManager(t, ca, testDomains)
	fake := newFakeACME(t, ca, "http://127.0.0.1:"+strconv.Itoa(mgr.httpPort))
	mgr.directoryURL = fake.directoryURL()
	mgr.stateDir = t.TempDir()
	mgr.stateReady = func() bool { return true }
	mgr.recheck = 10 * time.Millisecond
	mgr.retry = 10 * time.Millisecond
	return mgr, fake
}

// runFor runs the manager until cond holds or the deadline passes.
func runFor(t *testing.T, mgr *manager, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { mgr.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(30 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
	}
}

// A persisted certificate with most of its life left is served again after a
// restart, and the CA is not asked for another.
func TestRunReusesThePersistedCertificate(t *testing.T) {
	ca := newTestCA(t)
	mgr, fake := newStateManager(t, ca)
	var orders atomic.Int32
	fake.onNewOrder = func() { orders.Add(1) }
	keyPEM, chainPEM := backdatedCert(t, ca, testDomains, -10*24*time.Hour, 80*24*time.Hour)
	if err := mgr.persist(keyPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	runFor(t, mgr, func() bool {
		got, err := os.ReadFile(mgr.certPath())
		return err == nil && bytes.Equal(got, chainPEM)
	})
	time.Sleep(50 * time.Millisecond)
	if n := orders.Load(); n != 0 {
		t.Fatalf("%d orders sent for a certificate the state already held", n)
	}
	if got, _ := os.ReadFile(mgr.keyPath()); !bytes.Equal(got, keyPEM) {
		t.Fatal("served key is not the persisted one")
	}
}

// A persisted certificate past 2/3 of its life (under 30 days left of 90) is
// restored, then renewed, and the renewal replaces it in the state.
func TestRunRenewsAnAgingPersistedCertificate(t *testing.T) {
	ca := newTestCA(t)
	mgr, _ := newStateManager(t, ca)
	keyPEM, chainPEM := backdatedCert(t, ca, testDomains, -70*24*time.Hour, 20*24*time.Hour)
	if err := mgr.persist(keyPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	runFor(t, mgr, func() bool {
		saved, err := os.ReadFile(filepath.Join(mgr.stateDir, certFile))
		return err == nil && !bytes.Equal(saved, chainPEM) && !mgr.needsIssue()
	})
	served, _ := os.ReadFile(mgr.certPath())
	saved, _ := os.ReadFile(filepath.Join(mgr.stateDir, certFile))
	if !bytes.Equal(served, saved) {
		t.Fatal("the state does not hold the certificate being served")
	}
}

// An issuance lands in the state, and so does the ACME account key, so the
// next pod reuses both.
func TestIssuePersistsCertificateAndAccount(t *testing.T) {
	ca := newTestCA(t)
	mgr, _ := newStateManager(t, ca)
	runFor(t, mgr, func() bool { return !mgr.needsIssue() })

	for _, name := range []string{certFile, keyFile, accountKeyFile} {
		if _, err := os.Stat(filepath.Join(mgr.stateDir, name)); err != nil {
			t.Errorf("state lacks %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(mgr.keyDir, accountKeyFile)); err == nil {
		t.Error("account key written outside the state volume")
	}
	served, _ := os.ReadFile(mgr.keyPath())
	saved, _ := os.ReadFile(filepath.Join(mgr.stateDir, keyFile))
	if !bytes.Equal(served, saved) {
		t.Error("persisted key differs from the served key")
	}
}

// Nothing is ordered before the state volume is mounted: it may hold a
// certificate that makes the order redundant.
func TestRunWaitsForTheStateVolume(t *testing.T) {
	ca := newTestCA(t)
	mgr, fake := newStateManager(t, ca)
	var mounted atomic.Bool
	mgr.stateReady = mounted.Load
	var orders atomic.Int32
	fake.onNewOrder = func() { orders.Add(1) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { mgr.run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	if n := orders.Load(); n != 0 {
		cancel()
		<-done
		t.Fatalf("%d orders sent before the state volume was mounted", n)
	}
	if leaf, err := mgr.diskLeaf(); err != nil || !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		t.Fatal("no bootstrap placeholder for nginx while waiting")
	}
	mounted.Store(true)
	for deadline := time.Now().Add(30 * time.Second); mgr.needsIssue(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("never issued once the volume was mounted")
		}
	}
	cancel()
	<-done
}

// A state the sidecar cannot trust is not served; a fresh certificate is
// issued over it instead.
func TestRestoreRefusesABadState(t *testing.T) {
	ca := newTestCA(t)
	keyA, _ := backdatedCert(t, ca, testDomains, -time.Hour, 80*24*time.Hour)
	_, chainB := backdatedCert(t, ca, testDomains, -time.Hour, 80*24*time.Hour)
	for name, state := range map[string][2][]byte{
		"key of another certificate": {keyA, chainB},
		"not PEM":                    {[]byte("junk"), []byte("junk")},
	} {
		t.Run(name, func(t *testing.T) {
			mgr, _ := newStateManager(t, ca)
			if err := mgr.persist(state[0], state[1]); err != nil {
				t.Fatal(err)
			}
			if err := mgr.restore(); err == nil {
				t.Fatal("restored a bad state")
			}
			if !mgr.needsIssue() {
				t.Fatal("a bad state was installed")
			}
		})
	}
	t.Run("self-signed", func(t *testing.T) {
		mgr, _ := newStateManager(t, ca)
		if err := mgr.bootstrap(); err != nil {
			t.Fatal(err)
		}
		key, _ := os.ReadFile(mgr.keyPath())
		chain, _ := os.ReadFile(mgr.certPath())
		if err := mgr.persist(key, chain); err != nil {
			t.Fatal(err)
		}
		if err := mgr.restore(); err == nil {
			t.Fatal("restored the bootstrap placeholder")
		}
	})
	t.Run("empty volume", func(t *testing.T) {
		mgr, _ := newStateManager(t, ca)
		if err := mgr.restore(); err != nil {
			t.Fatalf("a new volume is not an error: %v", err)
		}
	})
}

// An order the first directory refuses with a rate limit goes to the
// fallback, without first waiting the limit out.
func TestIssueFallsBackOnARateLimit(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)
	primary := newFakeACME(t, ca, "http://127.0.0.1:"+strconv.Itoa(mgr.httpPort))
	primary.rateLimitNewOrder = true
	var primaryOrders atomic.Int32
	primary.onNewOrder = func() { primaryOrders.Add(1) }
	mgr.directoryURL = primary.directoryURL()
	fallback := newFakeACME(t, ca, "http://127.0.0.1:"+strconv.Itoa(mgr.httpPort))
	mgr.fallbackURL = fallback.directoryURL()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	mgr.ensure(ctx)
	if mgr.needsIssue() {
		t.Fatal("no certificate from the fallback directory")
	}
	if n := primaryOrders.Load(); n != 1 {
		t.Fatalf("the rate-limited directory saw %d orders, want 1 (no retry)", n)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("issuance took %s: the rate limit was waited out", d)
	}
}

// Without a fallback a rate limit is an ordinary failure, retried later.
func TestRateLimitWithoutFallbackFails(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)
	primary := newFakeACME(t, ca, "http://127.0.0.1:"+strconv.Itoa(mgr.httpPort))
	primary.rateLimitNewOrder = true
	mgr.directoryURL = primary.directoryURL()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := mgr.issueDomains(ctx, testDomains)
	if !rateLimited(err) {
		t.Fatalf("error = %v, want a rateLimited problem", err)
	}
}

func TestMountedFrom(t *testing.T) {
	const dir = "/var/lib/c8s acme"
	info := filepath.Join(t.TempDir(), "mountinfo")
	write := func(lines string) {
		if err := os.WriteFile(info, []byte(lines), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	emptyDir := "2250 2240 259:1 /pods/x/volumes/kubernetes.io~empty-dir/acme /var/lib/c8s\\040acme rw,relatime - ext4 /dev/vda1 rw\n"
	crypt := "2300 2250 252:3 / /var/lib/c8s\\040acme rw,relatime master:9 - ext4 /dev/mapper/c8s-crypt-uid-acme rw\n"

	write(emptyDir)
	if mountedFrom(info, dir, cryptMapperPrefix) {
		t.Error("the bare emptyDir counted as the encrypted volume")
	}
	write(emptyDir + crypt)
	if !mountedFrom(info, dir, cryptMapperPrefix) {
		t.Error("the encrypted volume over the emptyDir was not seen")
	}
	write(emptyDir + crypt + "2400 2300 0:99 / /var/lib/c8s\\040acme rw - tmpfs tmpfs rw\n")
	if mountedFrom(info, dir, cryptMapperPrefix) {
		t.Error("a mount over the encrypted volume was not noticed")
	}
	if mountedFrom(filepath.Join(t.TempDir(), "absent"), dir, cryptMapperPrefix) {
		t.Error("an unreadable mountinfo counted as mounted")
	}
}
