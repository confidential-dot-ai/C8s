package credrelease

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestNewCmdDefaultsAndHelp(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "cred-release" {
		t.Fatalf("Use = %q, want cred-release", cmd.Use)
	}

	defaults := []struct {
		name string
		want string
	}{
		{"listen", ":8443"},
		{"attestation-api-url", "http://127.0.0.1:8400"},
		{"platform", ""},
		{"client-ca-cert", defaultClientCACert},
		{"client-ca-key", defaultClientCAKey},
		{"server-ca-cert", defaultServerCACert},
		{"cert-ttl", "168h0m0s"},
		{"cert-org", "c8s:node-operators"},
		{"cert-cn", "operator"},
		{"log-cert-ttl", "168h0m0s"},
		{"log-cert-org", "c8s:log-readers"},
		{"log-cert-cn", "log-reader"},
	}
	flags := cmd.Flags()
	for _, tt := range defaults {
		flag := flags.Lookup(tt.name)
		if flag == nil {
			t.Errorf("flag %q not registered", tt.name)
			continue
		}
		if flag.DefValue != tt.want {
			t.Errorf("flag %q default = %q, want %q", tt.name, flag.DefValue, tt.want)
		}
	}

	// Omitting --platform is a usage error, not a tdx default.
	pf := flags.Lookup("platform")
	if pf == nil || pf.Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Errorf("--platform is not marked required")
	}
}
