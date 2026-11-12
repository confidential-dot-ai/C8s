//go:build c8s_dev

package cds

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// A test drives every command that dials a replica against mock-attested ones.
func TestDevCommandsVerifyReplicasThroughAnAttestationAPI(t *testing.T) {
	for _, cmd := range replicaDialers(t) {
		if cmd.Flags().Lookup("attestation-api-url") == nil {
			t.Errorf("%s has no --attestation-api-url in a c8s_dev build", cmd.CommandPath())
		}
	}
}

// Without the flag a replica is verified in-process, and a malformed URL is
// refused rather than leaving the in-process verifier in place.
func TestAttestationAPIFlagReplacesTheVerifier(t *testing.T) {
	var verifier cdsconn.PinVerifier = cdsconn.LocalVerifier{}
	flag := &attestationAPIFlag{verifier: &verifier}
	for _, malformed := range []string{"", "127.0.0.1:8400", "file:///run/api", "http://"} {
		if err := flag.Set(malformed); err == nil {
			t.Errorf("--attestation-api-url %q was accepted", malformed)
		}
	}
	if _, local := verifier.(cdsconn.LocalVerifier); !local {
		t.Fatalf("a refused URL replaced the verifier with %T", verifier)
	}
	if err := flag.Set("http://127.0.0.1:8400"); err != nil {
		t.Fatal(err)
	}
	if _, remote := verifier.(attestationAPIVerifier); !remote {
		t.Fatalf("the verifier is %T, want one through the attestation-api", verifier)
	}
}
