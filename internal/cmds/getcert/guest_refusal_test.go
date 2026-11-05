package getcert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func TestGuestRenewalKeepsFatalWithdrawalSeparateFromRefusalBackoff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		fatal   bool
	}{
		{"cannot withdraw credentials", fmt.Errorf("withdrawal failed: %w", errFailClosed), true},
		{"CDS refusal", &attestclient.StatusError{Status: http.StatusForbidden}, false},
		{"CDS rate limit", &attestclient.StatusError{Status: http.StatusTooManyRequests}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			attempts := 0
			previous := obtainCertFn
			obtainCertFn = func(context.Context, config, attestclient.Client, *credentials) error {
				attempts++
				if attempts == 2 {
					cancel()
				}
				return tc.failure
			}
			t.Cleanup(func() { obtainCertFn = previous })
			cfg := config{guest: &GuestConfig{}, InitialRetryInterval: time.Millisecond, RenewInterval: time.Hour}
			err := renewLoop(ctx, cfg, attestclient.Client{}, allowlistclient.Client{}, &credentials{})
			if tc.fatal {
				if !errors.Is(err, errFailClosed) || attempts != 1 {
					t.Fatalf("fatal withdrawal was retried: attempts=%d error=%v", attempts, err)
				}
			} else if err != nil || attempts != 2 {
				t.Fatalf("retryable refusal stopped guest renewal: attempts=%d error=%v", attempts, err)
			}
		})
	}
}
