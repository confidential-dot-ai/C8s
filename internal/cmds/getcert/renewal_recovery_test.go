package getcert

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func TestRenewalRecoversPromptlyAfterExpiryDuringIssuance(t *testing.T) {
	ca := newTestCA(t)
	creds := publishedCredentials(t, ca, 2*time.Second)
	previousKey, issuer := creds.current.Key, creds.issuer
	expiry := generationExpiry(creds.current)
	stageInventory(t, testInstanceID)
	cdsURL, attURL := startFakeServers(t, ca)
	cfg := config{
		CDSURL:                cdsURL,
		AttestationApiURL:     attURL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: time.Second,
		RenewInterval:         time.Hour,
		InitialRetryInterval:  100 * time.Millisecond,
	}
	ctx, cancel := context.WithDeadline(t.Context(), expiry.Add(2*time.Second))
	defer cancel()
	first := true
	recovered := false
	old := obtainCertFn
	t.Cleanup(func() { obtainCertFn = old })
	obtainCertFn = func(
		requestCtx context.Context,
		cfg config,
		client attestclient.Client,
		c *credentials,
	) error {
		if first {
			first = false
			deadline, ok := requestCtx.Deadline()
			if !ok || !deadline.Equal(expiry) {
				t.Fatalf("renewal deadline = %v, want certificate expiry %v", deadline, expiry)
			}
			<-requestCtx.Done()
			return requestCtx.Err()
		}
		if c.current != nil {
			t.Fatal("recovery started with the expired generation still published")
		}
		if _, err := c.volume.readPublished(c.volume.leafName); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired certificate remains readable: %v", err)
		}
		if err := obtainCert(requestCtx, cfg, client, c); err != nil {
			return err
		}
		recovered = true
		cancel()
		return nil
	}
	r := newRenewer(cfg, plaintextCDSClient(cdsURL), allowlistclient.Client{}, creds)
	defer r.stop()
	r.scheduleRenewal(0)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !recovered {
		t.Fatal("issuance is available, but credentials did not recover within 2s of expiry")
	}
	published, err := storedGeneration(creds.volume)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeneration(published, testInstanceID, issuer, time.Now()); err != nil {
		t.Fatalf("recovered generation violates the pod binding: %v", err)
	}
	if !leafMatchesKey(published) || published.Key.Equal(previousKey) {
		t.Fatal("recovery must publish a matching certificate and a fresh key")
	}
}

func TestRecoveryBackoffAdvancesUntilSuccessfulIssuance(t *testing.T) {
	ca := newTestCA(t)
	creds := publishedCredentials(t, ca, time.Hour)
	cfg := config{RenewInterval: time.Hour, InitialRetryInterval: time.Second}
	failed := true
	old := obtainCertFn
	t.Cleanup(func() { obtainCertFn = old })
	obtainCertFn = func(
		_ context.Context,
		_ config,
		_ attestclient.Client,
		c *credentials,
	) error {
		if failed {
			return errors.New("issuer unavailable")
		}
		g, err := issueFor(ca, c, time.Hour)
		if err != nil {
			return err
		}
		return c.publish(g, time.Now())
	}
	r := newRenewer(cfg, attestclient.Client{}, allowlistclient.Client{}, creds)
	defer r.stop()
	r.unpublishedRetry.RandomizationFactor = 0
	if err := creds.withdrawUnusable(generationExpiry(creds.current).Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	wantRetry := func(delay time.Duration) {
		t.Helper()
		before := time.Now()
		if err := r.renew(t.Context()); err != nil {
			t.Fatal(err)
		}
		if creds.current != nil {
			t.Fatal("failed issuance published credentials")
		}
		after := time.Now()
		if r.renewDue.Before(before.Add(delay)) || r.renewDue.After(after.Add(delay)) {
			t.Fatalf("next attempt due in %v, want %v", time.Until(r.renewDue), delay)
		}
	}
	wantRetry(time.Second)
	wantRetry(1500 * time.Millisecond)
	failed = false
	if err := r.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := creds.withdrawUnusable(generationExpiry(creds.current).Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	failed = true
	wantRetry(time.Second)
}

func TestRefusalsAdvanceUnpublishedBackoff(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg := config{RenewInterval: time.Hour, InitialRetryInterval: time.Second}
			creds := publishedCredentials(t, newTestCA(t), time.Hour)
			r := newRenewer(cfg, attestclient.Client{}, allowlistclient.Client{}, creds)
			defer r.stop()
			r.unpublishedRetry.RandomizationFactor = 0
			if err := creds.withdrawUnusable(generationExpiry(creds.current).Add(time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			var requestErr error = &attestclient.StatusError{Status: status}
			old := obtainCertFn
			t.Cleanup(func() { obtainCertFn = old })
			obtainCertFn = func(
				_ context.Context,
				_ config,
				_ attestclient.Client,
				_ *credentials,
			) error {
				return requestErr
			}
			wantRefusalRetry := func(ceiling time.Duration) {
				t.Helper()
				before := time.Now()
				if err := r.renew(t.Context()); err != nil {
					t.Fatal(err)
				}
				after := time.Now()
				if r.renewDue.Before(before.Add(ceiling/2)) || r.renewDue.After(after.Add(ceiling)) {
					t.Fatalf("refusal retry due in %v, want between %v and %v", time.Until(r.renewDue), ceiling/2, ceiling)
				}
			}
			wantRefusalRetry(time.Second)
			wantRefusalRetry(2 * time.Second)
			requestErr = errors.New("issuer unavailable")
			before := time.Now()
			if err := r.renew(t.Context()); err != nil {
				t.Fatal(err)
			}
			after := time.Now()
			want := 2250 * time.Millisecond
			if r.renewDue.Before(before.Add(want)) || r.renewDue.After(after.Add(want)) {
				t.Fatalf("retry after two refusals due in %v, want %v", time.Until(r.renewDue), want)
			}
		})
	}
}
