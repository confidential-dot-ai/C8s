package getcert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func namedLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	ext, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{
		Name:             "api",
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{0x11}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{Extensions: []pkix.Extension{ext}}
}

// expiring returns a copy of leaf that CDS just issued with the given TTL: no
// backdated NotBefore, exactly as certutil.NewLeafTemplate builds one.
func expiring(leaf *x509.Certificate, ttl time.Duration) *x509.Certificate {
	out := *leaf
	out.NotBefore = time.Now()
	out.NotAfter = out.NotBefore.Add(ttl)
	return &out
}

// pacing is what the next renewal delay is computed from: the published leaf
// and the expiries that bound the generation's life.
type pacing struct {
	leaf    *x509.Certificate
	leafTTL time.Duration
	caTTL   time.Duration
}

// paced is a published generation carrying nothing but those inputs.
func paced(p pacing) *Generation {
	return &Generation{
		Leaf:  expiring(p.leaf, p.leafTTL),
		CASet: []*x509.Certificate{{NotAfter: time.Now().Add(p.caTTL)}},
	}
}

func TestRenewalInterval(t *testing.T) {
	base := config{RenewInterval: 6 * time.Hour, RenewJitterPercent: defaultRenewJitterPercent, UnnamedRenewInterval: 30 * time.Second}

	t.Run("unnamed leaf fast-polls from 2s with bounded jitter", func(t *testing.T) {
		got := renewalInterval(base, paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 0)
		if got < 2*time.Second || got > 2500*time.Millisecond {
			t.Fatalf("interval = %v, want [2s, 2.5s]", got)
		}
	})
	t.Run("unnamed fast poll doubles up to unnamed-renew-interval", func(t *testing.T) {
		if got := renewalInterval(base, paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 2); got < 8*time.Second || got > 10*time.Second {
			t.Fatalf("third unnamed interval = %v, want [8s, 10s]", got)
		}
		if got := renewalInterval(base, paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 5); got < 30*time.Second || got > 38*time.Second {
			t.Fatalf("capped unnamed interval = %v, want [30s, ~37.5s]", got)
		}
	})
	t.Run("nil leaf counts as unnamed", func(t *testing.T) {
		if got := renewalInterval(base, nil, 0); got >= time.Minute {
			t.Fatalf("interval = %v, want fast", got)
		}
	})
	t.Run("named leaf settles to renew-interval", func(t *testing.T) {
		if got := renewalInterval(base, paced(pacing{leaf: namedLeaf(t), leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 0); got < 288*time.Minute || got > 6*time.Hour {
			t.Fatalf("interval = %v, want [4h48m, 6h]", got)
		}
	})
	t.Run("fast poll disabled by zero", func(t *testing.T) {
		cfg := base
		cfg.UnnamedRenewInterval = 0
		if got := renewalInterval(cfg, paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 0); got < 288*time.Minute || got > 6*time.Hour {
			t.Fatalf("interval = %v, want [4h48m, 6h]", got)
		}
	})
	t.Run("fast interval never exceeds renew-interval", func(t *testing.T) {
		cfg := base
		cfg.RenewInterval = 10 * time.Second
		if got := renewalInterval(cfg, paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 5); got < 8*time.Second || got > 10*time.Second {
			t.Fatalf("interval = %v, want the shorter renew-interval", got)
		}
	})
}

// The invariant: whatever the flags say, the next renewal must fire strictly
// before the installed leaf's NotAfter. The chart ships --renew-interval equal
// to the named-leaf TTL, so pacing on the flag alone would fire exactly at (or
// after) expiry.
func TestRenewalIntervalFiresBeforeLeafExpiry(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg config
		gen *Generation
	}{
		"named leaf at the chart's renew-interval == named TTL": {
			cfg: config{RenewInterval: issuer.MaxNamedLeafTTL, RenewJitterPercent: defaultRenewJitterPercent, UnnamedRenewInterval: 30 * time.Second},
			gen: paced(pacing{leaf: namedLeaf(t), leafTTL: issuer.MaxNamedLeafTTL, caTTL: 24 * time.Hour}),
		},
		"named leaf with a renew-interval far past its TTL": {
			cfg: config{RenewInterval: 24 * time.Hour, RenewJitterPercent: defaultRenewJitterPercent},
			gen: paced(pacing{leaf: namedLeaf(t), leafTTL: issuer.MaxNamedLeafTTL, caTTL: 365 * 24 * time.Hour}),
		},
		"unnamed leaf shorter than the fast poll": {
			cfg: config{RenewInterval: 6 * time.Hour, RenewJitterPercent: defaultRenewJitterPercent, UnnamedRenewInterval: 30 * time.Second},
			gen: paced(pacing{leaf: &x509.Certificate{}, leafTTL: 20 * time.Second, caTTL: 24 * time.Hour}),
		},
		"CA set expiring before the leaf": {
			cfg: config{RenewInterval: 6 * time.Hour, RenewJitterPercent: defaultRenewJitterPercent},
			gen: paced(pacing{leaf: namedLeaf(t), leafTTL: 6 * time.Hour, caTTL: 30 * time.Second}),
		},
	} {
		t.Run(name, func(t *testing.T) {
			remaining := time.Until(generationExpiry(tc.gen))
			if got := renewalInterval(tc.cfg, tc.gen, 0); got >= remaining {
				t.Fatalf("delay = %v, generation expires in %v: renewal would fire at or after expiry", got, remaining)
			}
		})
	}
}

// An already-expired leaf must not spin the loop, and the floor must never
// override a shorter operator-chosen --renew-interval.
func TestRenewalIntervalFloor(t *testing.T) {
	cfg := config{RenewInterval: time.Hour, RenewJitterPercent: defaultRenewJitterPercent}
	if got := renewalInterval(cfg, paced(pacing{leaf: &x509.Certificate{}, leafTTL: -time.Hour, caTTL: 24 * time.Hour}), 0); got != minRenewalDelay {
		t.Fatalf("expired leaf delay = %v, want the %v floor", got, minRenewalDelay)
	}
	cfg.RenewInterval = time.Second
	if got := renewalInterval(cfg, paced(pacing{leaf: &x509.Certificate{}, leafTTL: -time.Hour, caTTL: 24 * time.Hour}), 0); got != time.Second {
		t.Fatalf("delay = %v, want the operator's shorter --renew-interval", got)
	}
}

func TestRenewalIntervalSpreadsDefaultRefreshes(t *testing.T) {
	cfg := config{RenewInterval: 2 * time.Hour, RenewJitterPercent: defaultRenewJitterPercent}
	seen := map[time.Duration]bool{}
	for range 100 {
		got := renewalInterval(cfg, nil, 0)
		if got < 96*time.Minute || got > 2*time.Hour {
			t.Fatalf("delay = %v, want [1h36m, 2h]", got)
		}
		seen[got] = true
	}
	if len(seen) == 1 {
		t.Fatal("all refresh delays are identical")
	}
}

// Jitter is added before the clamp, so no delay may exceed --renew-interval —
// the probe that found this used 31s/30s, where +25% jitter overshot.
func TestRenewalIntervalJitterIsClamped(t *testing.T) {
	cfg := config{RenewInterval: 31 * time.Second, RenewJitterPercent: defaultRenewJitterPercent, UnnamedRenewInterval: 30 * time.Second}
	for range 500 {
		if got := renewalInterval(cfg, paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 0); got > cfg.RenewInterval {
			t.Fatalf("delay = %v exceeds --renew-interval %v", got, cfg.RenewInterval)
		}
	}
}

// A sub-4ns interval makes the jitter divisor zero, which mrand.Int64N panics
// on. validateConfig rejects such a value, but the pacer must not panic on one.
func TestRenewalIntervalTinyUnnamedIntervalDoesNotPanic(t *testing.T) {
	for _, iv := range []time.Duration{1, 2, 3, 4} {
		cfg := config{RenewInterval: time.Hour, RenewJitterPercent: defaultRenewJitterPercent, UnnamedRenewInterval: iv}
		if got := renewalInterval(cfg, paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 0); got <= 0 {
			t.Fatalf("unnamed interval %v: delay = %v, want positive", iv, got)
		}
	}
}

// A permanently-unnamed pod must not attest every --unnamed-renew-interval for
// its whole lifetime: the fast poll backs off toward --renew-interval.
func TestRenewalIntervalUnnamedBacksOff(t *testing.T) {
	cfg := config{RenewInterval: time.Hour, RenewJitterPercent: defaultRenewJitterPercent, UnnamedRenewInterval: 30 * time.Second}
	gen := paced(pacing{leaf: &x509.Certificate{}, leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour})

	steady := renewalInterval(cfg, gen, unnamedBackoffAfter)
	if steady > 38*time.Second {
		t.Fatalf("delay before backoff = %v, want the fast poll", steady)
	}
	if got := renewalInterval(cfg, gen, unnamedBackoffAfter+4); got < 8*steady {
		t.Fatalf("delay after 4 backoff steps = %v, want at least 8x the fast poll", got)
	}
	if got := renewalInterval(cfg, gen, 1000); got < 48*time.Minute || got > cfg.RenewInterval {
		t.Fatalf("delay for a permanently unnamed pod = %v, want [48m, 1h]", got)
	}
	// A leaf that gets named resets to the ordinary interval.
	if got := renewalInterval(cfg, paced(pacing{leaf: namedLeaf(t), leafTTL: 24 * time.Hour, caTTL: 24 * time.Hour}), 1000); got < 48*time.Minute || got > cfg.RenewInterval {
		t.Fatalf("named delay = %v, want [48m, 1h]", got)
	}
}

// A failed renewal retries on a short backoff, never slower than the ordinary
// pacing — the installed leaf may be minutes from expiry.
func TestRenewalRetryInterval(t *testing.T) {
	cfg := config{RenewInterval: 6 * time.Hour, RenewJitterPercent: defaultRenewJitterPercent}
	gen := paced(pacing{leaf: namedLeaf(t), leafTTL: 6 * time.Hour, caTTL: 24 * time.Hour})

	first := renewalRetryInterval(cfg, gen, 1)
	if first != renewalRetryBase {
		t.Fatalf("first retry = %v, want %v", first, renewalRetryBase)
	}
	if second := renewalRetryInterval(cfg, gen, 2); second != 2*renewalRetryBase {
		t.Fatalf("second retry = %v, want %v", second, 2*renewalRetryBase)
	}
	// Never past the ordinary pacing ceiling; each call samples fresh jitter.
	for _, failures := range []int{1, 5, 50} {
		ceiling := min(cfg.RenewInterval, time.Until(generationExpiry(gen))/2)
		if got := renewalRetryInterval(cfg, gen, failures); got > ceiling {
			t.Fatalf("retry after %d failures = %v, exceeds the pacing ceiling %v", failures, got, ceiling)
		}
	}
	// An expiring leaf shortens the retry below the base delay.
	if got := renewalRetryInterval(cfg, paced(pacing{leaf: namedLeaf(t), leafTTL: 12 * time.Second, caTTL: 24 * time.Hour}), 9); got > 12*time.Second {
		t.Fatalf("retry = %v, want under the leaf's remaining 12s", got)
	}
}

func TestValidateConfigUnnamedRenewInterval(t *testing.T) {
	base := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://localhost:8400",
		SAN:               "workload.example.com",
	}
	for _, iv := range []time.Duration{-time.Second, 1, 999 * time.Millisecond} {
		cfg := base
		cfg.UnnamedRenewInterval = iv
		if err := validateConfig(cfg); !errors.Is(err, errInvalidUnnamedRenewInterval) {
			t.Fatalf("--unnamed-renew-interval=%v: err = %v, want errInvalidUnnamedRenewInterval", iv, err)
		}
	}
	for _, iv := range []time.Duration{0, time.Second, 30 * time.Second} {
		cfg := base
		cfg.UnnamedRenewInterval = iv
		if err := validateConfig(cfg); err != nil {
			t.Fatalf("--unnamed-renew-interval=%v: unexpected error %v", iv, err)
		}
	}
}
