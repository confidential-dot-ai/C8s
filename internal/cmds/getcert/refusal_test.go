package getcert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestRefused(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("attestation failed: %w", &attestclient.StatusError{Status: 403, Body: `{"code":"csr_denied"}`}), true},
		{fmt.Errorf("authenticate: %w", &attestclient.StatusError{Status: 429, Body: "rate limit exceeded"}), true},
		{fmt.Errorf("fetch sandbox token: %w", workloadclaims.ErrSandboxRefused), true},
		{fmt.Errorf("authenticate: %w", &attestclient.StatusError{Status: 503}), false},
		{errors.New("dial tcp 10.0.2.2:30808: connect: connection refused"), false},
		{nil, false},
	} {
		if got := refused(tc.err); got != tc.want {
			t.Errorf("refused(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestRefusedRetryInterval(t *testing.T) {
	cfg := config{InitialRetryInterval: 2 * time.Second}
	for refusals, want := range map[int]time.Duration{
		1:  2 * time.Second,
		2:  4 * time.Second,
		5:  32 * time.Second,
		9:  maxRefusedRetryInterval,
		50: maxRefusedRetryInterval,
	} {
		for range 50 {
			if got := refusedRetryInterval(cfg, refusals); got < want/2 || got > want {
				t.Fatalf("retry after %d refusals = %v, want within [%v, %v]", refusals, got, want/2, want)
			}
		}
	}
}

// #1068: a pod whose leaf is unnamed, as one refused right after issuance
// stays, retried a failed renewal at the unnamed fast poll forever.
func TestRenewalRetryIntervalUnnamedBacksOff(t *testing.T) {
	cfg := config{
		RenewInterval:        2 * time.Hour,
		UnnamedRenewInterval: 30 * time.Second,
		InitialRetryInterval: 2 * time.Second,
	}
	unnamed := paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour})
	if got := renewalRetryInterval(cfg, unnamed, 5, 0); got != 16*renewalRetryBase {
		t.Fatalf("retry after 5 failures on an unnamed leaf = %v, want %v", got, 16*renewalRetryBase)
	}
	if got := renewalRetryInterval(cfg, unnamed, 20, 20); got < maxRefusedRetryInterval/2 {
		t.Fatalf("retry after 20 refusals on an unnamed leaf = %v, want at least %v", got, maxRefusedRetryInterval/2)
	}
	// A refusal never waits past the generation's remaining lifetime.
	short := paced(pacing{leaf: namedLeaf(t), leafTTL: 12 * time.Second, caTTL: 24 * time.Hour})
	if got := renewalRetryInterval(cfg, short, 20, 20); got > 12*time.Second {
		t.Fatalf("retry = %v, want under the leaf's remaining 12s", got)
	}
}

func TestObtainCertWithRetryBacksOffOnRefusal(t *testing.T) {
	attempts := stubObtainCertMinting(t, func(*credentials, int) (*generation, error) {
		return nil, fmt.Errorf("authenticate: %w", &attestclient.StatusError{Status: 429, Body: "rate limit exceeded"})
	})
	cfg := config{InitialRetryTimeout: 400 * time.Millisecond, InitialRetryInterval: 10 * time.Millisecond}
	if err := obtainCertWithRetry(t.Context(), cfg, attestclient.Client{}, testCredentials(t)); !refused(err) {
		t.Fatalf("obtainCertWithRetry = %v, want the refusal", err)
	}
	// At the constant 10ms pace this is ~40 attempts; doubling from 10ms
	// fits at most 8 in 400ms.
	if n := len(attempts()); n < 2 || n > 8 {
		t.Fatalf("%d attempts in %v, want 2-8 on a doubling backoff", n, cfg.InitialRetryTimeout)
	}
}
