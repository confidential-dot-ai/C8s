//go:build linux

package armtlsmesh

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// The flag help and the README both document the two node address sources
// and the startup failure.
func TestAttestationURLHelpNamesNodeAddressSources(t *testing.T) {
	fs := pflag.NewFlagSet("armtls-mesh", pflag.ContinueOnError)
	bindProxyFlags(fs, &proxyConfig{})
	if usage := fs.Lookup("attestation-api-url").Usage; !strings.HasSuffix(usage, cmdsutil.NodeAddressHelp) {
		t.Errorf("--attestation-api-url usage = %q, want it to end with cmdsutil.NodeAddressHelp", usage)
	}
	readme, err := os.ReadFile("../../../cmd/armtls-mesh/README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"`$(NODE_IP)`", "`" + cmdsutil.NodeIPPath + "`", "`$(HOST_IP)`", "startup fails"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("README does not mention %s", want)
		}
	}
}
