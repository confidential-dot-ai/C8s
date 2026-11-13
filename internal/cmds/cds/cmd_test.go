package cds

import (
	"testing"
	"time"
)

// TestNewCmdDurationFlagDefaults pins the built-in value of every duration
// setting: these values are operational contracts (cert lifetimes, rotation
// cadence, timeouts), so a silent change must fail a test.
func TestNewCmdDurationFlagDefaults(t *testing.T) {
	cfg := builtInConfig()
	for _, tc := range []struct {
		setting string
		value   time.Duration
		want    string
	}{
		{"ca-cert-validity", cfg.caCertValidity, "8760h0m0s"},
		{"cert-ttl", cfg.certTTL, "24h0m0s"},
		{"challenge-ttl", cfg.challengeTTL, "1m0s"},
		{"request-timeout", cfg.requestTimeout, "5s"},
		{"read-timeout", cfg.readTimeout, "10s"},
		{"read-header-timeout", cfg.readHeaderTimeout, "5s"},
		{"write-timeout", cfg.writeTimeout, "10s"},
		{"idle-timeout", cfg.idleTimeout, "20s"},
		{"readiness-interval", cfg.readinessInterval, "10s"},
		{"min-ca-validity", cfg.minCAValidity, "1h0m0s"},
		{"rate-limiter-evict-interval", cfg.rateLimiterEvictInterval, "1m0s"},
		{"rate-limiter-idle-timeout", cfg.rateLimiterIdleTimeout, "5m0s"},
		{"armtls-cert-ttl", cfg.armtlsCertTTL, "24h0m0s"},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			if got := tc.value.String(); got != tc.want {
				t.Fatalf("%s = %q, want %q", tc.setting, got, tc.want)
			}
		})
	}
}

// CDS takes no kubeconfig: client-go runs a kubeconfig's exec credential
// plugin, so a path in the pinned arguments' place would load pod-chosen code.
func TestNewCmdTakesNoKubeconfig(t *testing.T) {
	if f := NewCmd().Flags().Lookup("kubeconfig"); f != nil {
		t.Fatal("cds defines --kubeconfig")
	}
}
