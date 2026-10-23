//go:build linux

package armtlsmesh

import (
	"strings"
	"testing"
)

// The CLI refuses an endpoint it cannot run, before it binds anything: a
// positional argument, no credential paths, and credential paths one
// generation pointer cannot cover.
func TestRunRefusesAnEndpointItCannotRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"positional argument", []string{"node-endpoint"}, "unknown command"},
		{"no credential paths", nil, "required flag"},
		{"credential paths in two directories", []string{
			"--cert-path=/run/certs/tls.crt",
			"--key-path=/run/keys/tls.key",
			"--ca-path=/run/certs/ca.crt",
		}, "one directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Run(tc.args)
			if err == nil {
				t.Fatalf("Run(%q) was accepted", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Run(%q) = %v, want an error naming %q", tc.args, err, tc.want)
			}
		})
	}
}
