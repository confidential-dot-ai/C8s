package getcert

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func TestRenewalWithdrawsAtExpiryDuringBlockedOperations(t *testing.T) {
	for _, tt := range []struct {
		name          string
		leafTTL       time.Duration
		caTTL         time.Duration
		renewInterval time.Duration
		watchInterval time.Duration
		named         bool
		blockIssuance bool
		startupRetry  bool
	}{
		{
			name:          "issuance",
			leafTTL:       2 * time.Second,
			renewInterval: 10 * time.Millisecond,
			blockIssuance: true,
		},
		{
			name:          "CA expiry",
			leafTTL:       time.Hour,
			caTTL:         2 * time.Second,
			renewInterval: 10 * time.Millisecond,
			blockIssuance: true,
		},
		{
			name:          "CA watch",
			leafTTL:       2 * time.Second,
			renewInterval: time.Hour,
			watchInterval: 10 * time.Millisecond,
			blockIssuance: true,
		},
		{
			name:          "policy watch",
			leafTTL:       2 * time.Second,
			renewInterval: time.Hour,
			watchInterval: 10 * time.Millisecond,
			named:         true,
			blockIssuance: true,
		},
		{
			name:          "retry floor",
			leafTTL:       7 * time.Second,
			renewInterval: time.Hour,
		},
		{
			name:          "startup retry",
			leafTTL:       2 * time.Second,
			renewInterval: time.Hour,
			startupRetry:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ca := newTestCA(t)
			if tt.caTTL > 0 {
				ca = ca.issueSelf(t, tt.caTTL)
			}
			creds := publishedCredentials(t, ca, tt.leafTTL)
			if tt.named {
				g, err := issueNamedFor(ca, creds, tt.leafTTL)
				if err != nil {
					t.Fatal(err)
				}
				if err := creds.publish(g, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			expiry := generationExpiry(creds.current)
			cfg := config{
				RenewInterval:   tt.renewInterval,
				CAWatchInterval: tt.watchInterval,
				CAPath:          filepath.Join(creds.volume.dir, creds.volume.caName),
			}
			started := make(chan struct{}, 1)
			old := obtainCertFn
			obtainCertFn = func(ctx context.Context, _ config, _ attestclient.Client, _ *credentials) error {
				select {
				case started <- struct{}{}:
				default:
				}
				if tt.blockIssuance {
					<-ctx.Done()
					return ctx.Err()
				}
				return errors.New("issuance unavailable")
			}
			t.Cleanup(func() { obtainCertFn = old })
			pem := ca.pem(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.named && r.URL.Path == "/ca" {
					_, _ = w.Write([]byte(pem))
					return
				}
				select {
				case started <- struct{}{}:
				default:
				}
				<-r.Context().Done()
			}))
			defer srv.Close()
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				if tt.startupRetry {
					cfg.InitialRetryTimeout = time.Minute
					cfg.InitialRetryInterval = 5 * time.Second
					done <- obtainCertWithRetry(ctx, cfg, plaintextCDSClient(srv.URL), creds)
					return
				}
				done <- renewLoop(ctx, cfg, plaintextCDSClient(srv.URL), plaintextPolicyClient(srv.URL), creds)
			}()
			defer func() {
				cancel()
				<-done
			}()
			select {
			case <-started:
			case <-time.After(6 * time.Second):
				t.Fatal("operation did not start")
			}
			time.Sleep(time.Until(expiry) + 100*time.Millisecond)
			if _, err := os.Stat(cfg.CAPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expired generation still readable during %s: %v", tt.name, err)
			}
		})
	}
}

func TestForeignCAWatchPreservesRenewalBackoff(t *testing.T) {
	ca := newTestCA(t)
	creds := publishedCredentials(t, ca, time.Hour)
	foreignPEM := newTestCA(t).pem(t)
	url := startFakeCAServer(t, func() string {
		return foreignPEM
	})
	cfg := config{
		RenewInterval:   200 * time.Millisecond,
		CAWatchInterval: 10 * time.Millisecond,
		CAPath:          filepath.Join(creds.volume.dir, creds.volume.caName),
	}
	attempts := stubObtainCertFailing(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- renewLoop(ctx, cfg, plaintextCDSClient(url), plaintextPolicyClient(url), creds)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	at := waitForAttempts(t, attempts, 3)
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < 150*time.Millisecond {
			t.Fatalf("foreign CA watch shortened retry interval to %v", gap)
		}
	}
}

func TestRenewalRefreshesGenerationDeadline(t *testing.T) {
	ca := newTestCA(t)
	creds := publishedCredentials(t, ca, 2*time.Second)
	oldExpiry := generationExpiry(creds.current)
	renewedCA := ca.issueSelf(t, 48*time.Hour)
	attempts := stubObtainCert(t, renewedCA, func(int) (time.Duration, error) {
		return time.Hour, nil
	})
	cfg := config{
		RenewInterval:   time.Hour,
		CAWatchInterval: 10 * time.Millisecond,
		CAPath:          filepath.Join(creds.volume.dir, creds.volume.caName),
	}
	renewedPEM := renewedCA.pem(t)
	url := startFakeCAServer(t, func() string {
		return renewedPEM
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- renewLoop(ctx, cfg, plaintextCDSClient(url), plaintextPolicyClient(url), creds)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	waitForAttempts(t, attempts, 1)
	time.Sleep(time.Until(oldExpiry) + 100*time.Millisecond)
	if _, err := os.Stat(cfg.CAPath); err != nil {
		t.Fatalf("renewed generation withdrawn at predecessor expiry: %v", err)
	}
	if got := len(attempts()); got != 1 {
		t.Fatalf("renewed %d times after the generation deadline changed, want 1", got)
	}
}
