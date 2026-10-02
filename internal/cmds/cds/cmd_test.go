package cds

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// TestNewCmdDurationFlagDefaults pins the shipped default for every duration
// flag: these values are operational contracts (cert lifetimes, rotation
// cadence, timeouts), so a silent change must fail a test.
func TestNewCmdDurationFlagDefaults(t *testing.T) {
	flags := NewCmd().Flags()
	for _, tc := range []struct {
		flag string
		want string
	}{
		{"ca-cert-validity", "8760h0m0s"},
		{"cert-ttl", "24h0m0s"},
		{"challenge-ttl", "1m0s"},
		{"request-timeout", "5s"},
		{"read-timeout", "10s"},
		{"read-header-timeout", "5s"},
		{"write-timeout", "10s"},
		{"idle-timeout", "20s"},
		{"readiness-interval", "10s"},
		{"min-ca-validity", "1h0m0s"},
		{"rate-limiter-evict-interval", "1m0s"},
		{"rate-limiter-idle-timeout", "5m0s"},
		{"ratls-cert-ttl", "24h0m0s"},
		{"allowlist-activation-lease", "1m0s"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			f := flags.Lookup(tc.flag)
			if f == nil {
				t.Fatalf("missing --%s flag", tc.flag)
			}
			if f.DefValue != tc.want {
				t.Fatalf("default --%s = %q, want %q", tc.flag, f.DefValue, tc.want)
			}
		})
	}
}

func TestNewCmdRequiresRATLSPlatform(t *testing.T) {
	flag := NewCmd().Flags().Lookup("ratls-platform")
	if flag == nil {
		t.Fatal("missing --ratls-platform flag")
	}
	// No default: a silently-assumed TEE must never serve RA-TLS.
	if flag.DefValue != "" {
		t.Fatalf("default --ratls-platform = %q, want required with no default", flag.DefValue)
	}
	if flag.Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Fatal("--ratls-platform is not marked required")
	}

	_, _, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: func(context.Context, string) (string, error) { return "", nil },
	})
	if err != nil {
		t.Fatalf("documented --ratls-platform value is not accepted by ratls: %v", err)
	}
}

func TestValidateRATLSPlatformFlag(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantErr string
	}{
		{"sev-snp", ""},
		{"snp", ""}, // alias, normalized
		{"tdx", ""},
		{"", "must not be empty"},
		{"foo", "--ratls-platform:"},
	} {
		err := validateRATLSPlatformFlag(tc.in)
		if tc.wantErr == "" && err != nil {
			t.Errorf("validateRATLSPlatformFlag(%q) = %v, want nil", tc.in, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("validateRATLSPlatformFlag(%q) = %v, want substring %q", tc.in, err, tc.wantErr)
		}
	}
}

func TestValidateActivationLease(t *testing.T) {
	for _, tc := range []struct {
		lease time.Duration
		ok    bool
	}{
		{0, true},
		{time.Second, true},
		{60 * time.Second, true},
		{-time.Second, false},
		{500 * time.Millisecond, false},
	} {
		if err := validateActivationLease(tc.lease); (err == nil) != tc.ok {
			t.Errorf("validateActivationLease(%s) = %v, want ok=%v", tc.lease, err, tc.ok)
		}
	}
}
