package main

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// Each command that expands a node address reference in its attestation-api
// URL says where the address comes from and that startup fails without it.
func TestAttestationURLHelpNamesNodeAddressSources(t *testing.T) {
	for _, name := range []string{"cds", "get-cert", "allowlist-proxy", "cds-attest"} {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil || cmd.Name() != name {
			t.Fatalf("rootCmd.Find(%q) = %v, %v", name, cmd.Name(), err)
		}
		f := cmd.Flags().Lookup("attestation-api-url")
		if f == nil {
			t.Fatalf("%s has no --attestation-api-url", name)
		}
		if !strings.HasSuffix(f.Usage, cmdsutil.NodeAddressHelp) {
			t.Errorf("%s --attestation-api-url usage = %q, want it to end with cmdsutil.NodeAddressHelp", name, f.Usage)
		}
	}
}
