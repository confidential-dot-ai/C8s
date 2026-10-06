package cds

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
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
		{"armtls-cert-ttl", "24h0m0s"},
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

func TestNewCmdRequiresARMTLSPlatform(t *testing.T) {
	flag := NewCmd().Flags().Lookup("armtls-platform")
	if flag == nil {
		t.Fatal("missing --armtls-platform flag")
	}
	// No default: a silently-assumed TEE must never serve ARmTLS.
	if flag.DefValue != "" {
		t.Fatalf("default --armtls-platform = %q, want required with no default", flag.DefValue)
	}
	if flag.Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Fatal("--armtls-platform is not marked required")
	}

	_, _, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: func(context.Context, string) (string, error) { return "", nil },
	})
	if err != nil {
		t.Fatalf("documented --armtls-platform value is not accepted by armtls: %v", err)
	}
}

func TestValidateARMTLSPlatformFlag(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantErr string
	}{
		{"sev-snp", ""},
		{"snp", ""}, // alias, normalized
		{"tdx", ""},
		{"", "must not be empty"},
		{"foo", "--armtls-platform:"},
	} {
		err := validateARMTLSPlatformFlag(tc.in)
		if tc.wantErr == "" && err != nil {
			t.Errorf("validateARMTLSPlatformFlag(%q) = %v, want nil", tc.in, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("validateARMTLSPlatformFlag(%q) = %v, want substring %q", tc.in, err, tc.wantErr)
		}
	}
}
