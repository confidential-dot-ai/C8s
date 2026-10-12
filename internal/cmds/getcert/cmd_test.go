package getcert

import (
	"testing"
)

func TestNewCmdFlagDefaultsAndRequired(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "get-cert" {
		t.Fatalf("Use = %q, want get-cert", cmd.Use)
	}

	flags := cmd.Flags()
	// All three published files are required: a generation is atomic only if
	// one pointer covers the leaf, the key and the CA.
	for _, name := range []string{"cds-url", "attestation-api-url", "cert-path", "key-path", "ca-path"} {
		flag := flags.Lookup(name)
		if flag == nil {
			t.Fatalf("flag %q not registered", name)
		}
		if _, ok := flag.Annotations[`cobra_annotation_bash_completion_one_required_flag`]; !ok {
			t.Errorf("flag %q not marked required", name)
		}
	}

	tests := []struct {
		name string
		want string
	}{
		{"san", ""},
		{"san-file", ""},
		{"no-san", "false"},
		{"discovery-public-tls-mode", "cds"},
		{"reload-watch-interval", "1m0s"},
		{"ca-watch-interval", "0s"},
		{"initial-retry-timeout", "2m0s"},
		{"initial-retry-interval", "2s"},
		{"reload-nginx", "true"},
		{"workload-claims-timeout", "5s"},
	}
	for _, tt := range tests {
		flag := flags.Lookup(tt.name)
		if flag == nil {
			t.Fatalf("flag %q not registered", tt.name)
		}
		if flag.DefValue != tt.want {
			t.Errorf("flag %q default = %q, want %q", tt.name, flag.DefValue, tt.want)
		}
	}
}
