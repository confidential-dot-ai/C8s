package cds

import (
	"testing"

	"github.com/spf13/cobra"
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

// CDS takes no kubeconfig: client-go runs a kubeconfig's exec credential
// plugin, so a path in the pinned arguments' place would load pod-chosen code.
func TestNewCmdTakesNoKubeconfig(t *testing.T) {
	if f := NewCmd().Flags().Lookup("kubeconfig"); f != nil {
		t.Fatal("cds defines --kubeconfig")
	}
}

// replicaDialers are the `ha` commands that read or post to a replica, each of
// which verifies it against --cds-pin.
func replicaDialers(t *testing.T) []*cobra.Command {
	t.Helper()
	var dialers []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.Flags().Lookup("cds-pin") != nil {
			dialers = append(dialers, cmd)
		}
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(newHACmd())
	// status, decrees, pin-policy and the eight decree kinds.
	if len(dialers) != 11 {
		t.Fatalf("found %d ha commands that dial a replica, want 11", len(dialers))
	}
	return dialers
}
