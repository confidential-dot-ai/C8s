package objectstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCredentials(expires time.Time) TemporaryCredentials {
	return TemporaryCredentials{
		AccessKeyID:     "synthetic-access",
		SecretAccessKey: "synthetic-secret",
		SessionToken:    "synthetic-session",
		ExpiresAt:       expires,
	}
}

func TestCredentialProviderExpiresWithoutAmbientFallback(t *testing.T) {
	t.Setenv(
		"AWS_ACCESS_KEY_ID",
		"ambient-access",
	)
	t.Setenv(
		"AWS_SECRET_ACCESS_KEY",
		"ambient-secret",
	)
	start := time.Unix(
		2_000_000_000,
		0,
	)
	var clock atomic.Int64
	clock.Store(start.Unix())
	provider := NewCredentialProvider(func() time.Time {
		return time.Unix(
			clock.Load(),
			0,
		)
	})
	if _, err := provider.Retrieve(t.Context()); !errors.Is(
		err,
		ErrCredentialsUnavailable,
	) {
		t.Fatal("unprovisioned provider accepted ambient credentials")
	}
	first := testCredentials(start.Add(15 * time.Minute))
	if err := provider.Install(first); err != nil {
		t.Fatal(err)
	}
	loaded, err := provider.Retrieve(t.Context())
	if err != nil || loaded.AccessKeyID != first.AccessKeyID || !loaded.CanExpire || !loaded.Expires.Equal(first.ExpiresAt) {
		t.Fatal("installed session was not returned with its expiration")
	}
	clock.Store(first.ExpiresAt.Unix())
	if _, err := provider.Retrieve(t.Context()); !errors.Is(
		err,
		ErrCredentialsUnavailable,
	) {
		t.Fatal("expired session was returned")
	}
	clock.Store(start.Unix())
	different := first
	different.SessionToken = "different-session"
	if err := provider.Install(different); !errors.Is(
		err,
		ErrCredentialsStale,
	) {
		t.Fatal("clock rollback replaced a session without advancing expiration")
	}
	renewed := testCredentials(start.Add(30 * time.Minute))
	renewed.AccessKeyID = "renewed-access"
	if err := provider.Install(renewed); err != nil {
		t.Fatal(err)
	}
	loaded, err = provider.Retrieve(t.Context())
	if err != nil || loaded.AccessKeyID != renewed.AccessKeyID {
		t.Fatal("renewal was hidden behind a stale credential snapshot")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := provider.Retrieve(ctx); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal("canceled retrieval returned credentials")
	}
}

func TestCredentialProviderAcknowledgesOnlyIdenticalCurrentSession(t *testing.T) {
	now := time.Now()
	provider := NewCredentialProvider(func() time.Time { return now })
	first := testCredentials(now.Add(15 * time.Minute))
	if err := provider.Install(first); err != nil {
		t.Fatal(err)
	}
	installed := provider.current.Load()
	if err := provider.Install(first); err != nil || provider.current.Load() != installed {
		t.Fatal("identical session replaced its snapshot or was refused")
	}
	for _, change := range []func(*TemporaryCredentials){
		func(c *TemporaryCredentials) { c.AccessKeyID += "x" },
		func(c *TemporaryCredentials) { c.SecretAccessKey += "x" },
		func(c *TemporaryCredentials) { c.SessionToken += "x" },
	} {
		different := first
		change(&different)
		if err := provider.Install(different); !errors.Is(
			err,
			ErrCredentialsStale,
		) {
			t.Fatal("different session with equal expiry was accepted")
		}
	}
	now = first.ExpiresAt
	if err := provider.Install(first); err == nil {
		t.Fatal("duplicate session revived expired credentials")
	}
	newer := testCredentials(now.Add(10 * time.Minute))
	if err := provider.Install(newer); err != nil {
		t.Fatal(err)
	}
	now = first.ExpiresAt.Add(-time.Minute)
	if err := provider.Install(first); !errors.Is(
		err,
		ErrCredentialsStale,
	) {
		t.Fatal("old identical session replaced the current renewal")
	}
}

func TestCredentialProviderRejectsBadOrReplayedSessionsWithoutAdvancingFloor(t *testing.T) {
	now := time.Now()
	provider := NewCredentialProvider(func() time.Time { return now })
	first := testCredentials(now.Add(15 * time.Minute))
	if err := provider.Install(first); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*TemporaryCredentials){
		"empty access key":        func(c *TemporaryCredentials) { c.AccessKeyID = "" },
		"empty secret":            func(c *TemporaryCredentials) { c.SecretAccessKey = "" },
		"missing temporary token": func(c *TemporaryCredentials) { c.SessionToken = "" },
		"control character":       func(c *TemporaryCredentials) { c.SessionToken = "token\n" },
		"oversize token": func(c *TemporaryCredentials) {
			c.SessionToken = strings.Repeat(
				"a",
				(16<<10)+1,
			)
		},
		"expired":                           func(c *TemporaryCredentials) { c.ExpiresAt = now },
		"unbounded lifetime":                func(c *TemporaryCredentials) { c.ExpiresAt = now.Add(time.Hour + time.Nanosecond) },
		"same expiration different session": func(c *TemporaryCredentials) { c.ExpiresAt = first.ExpiresAt },
		"older session":                     func(c *TemporaryCredentials) { c.ExpiresAt = first.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(
			name,
			func(t *testing.T) {
				bad := testCredentials(now.Add(45 * time.Minute))
				bad.AccessKeyID = "different-access"
				change(&bad)
				if err := provider.Install(bad); err == nil {
					t.Fatal("invalid or stale session was installed")
				}
				loaded, err := provider.Retrieve(t.Context())
				if err != nil || loaded.AccessKeyID != first.AccessKeyID {
					t.Fatal("refused session changed current credentials")
				}
			},
		)
	}
	if err := provider.Install(testCredentials(now.Add(30 * time.Minute))); err != nil {
		t.Fatal("rejected credentials advanced the expiration floor")
	}
}

func TestCredentialProviderConcurrentReadersSeeCompleteRenewals(t *testing.T) {
	now := time.Now()
	provider := NewCredentialProvider(func() time.Time { return now })
	session := func(index int) TemporaryCredentials {
		value := fmt.Sprint(index)
		return TemporaryCredentials{
			AccessKeyID:     value,
			SecretAccessKey: value,
			SessionToken:    value,
			ExpiresAt:       now.Add(15*time.Minute + time.Duration(index)*time.Second),
		}
	}
	if err := provider.Install(session(0)); err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		readers.Go(func() {
			<-start
			for range 1000 {
				credentials, err := provider.Retrieve(t.Context())
				if err != nil || credentials.AccessKeyID != credentials.SecretAccessKey || credentials.AccessKeyID != credentials.SessionToken {
					t.Error("reader observed a partial credential renewal")
					return
				}
			}
		})
	}
	close(start)
	for index := 1; index <= 100; index++ {
		if err := provider.Install(session(index)); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
	last, err := provider.Retrieve(t.Context())
	if err != nil || last.AccessKeyID != "100" {
		t.Fatal("renewal did not publish the final session")
	}
}
