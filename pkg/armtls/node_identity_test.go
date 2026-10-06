package armtls

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// The policy must survive Pins conversion and the complete certificate
// verification path, not just the standalone claims checker.
func TestVerifyCertRequiresServerLaunchKey(t *testing.T) {
	_, att, cert := testAttestedCert(t, nil)
	digest := att.Report[0x90:0xc0]
	server, agent := []byte("server key"), []byte("agent key")
	stub := mockapi.New(t)
	policy := Pins{Images: []remote.ImagePin{{Name: "server", Digest: digest, Anchor: server}}}.VerifyPolicy(stub.URL())
	for _, tc := range []struct {
		name   string
		key    []byte
		accept bool
	}{
		{"server", server, true}, {"agent same image", agent, false}, {"missing binding", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := mockapi.PassingVerdict(hex.EncodeToString(digest))
			if tc.key != nil {
				binding := runtimemeasure.HostData(tc.key)
				verdict.Claims.InitData = binding[:]
			}
			stub.SetVerdict(verdict)
			_, err := VerifyCert(cert, policy, nil)
			if tc.accept && err != nil {
				t.Fatalf("server rejected: %v", err)
			}
			if !tc.accept && !errors.Is(err, ErrPolicyViolation) {
				t.Fatalf("unauthorized node accepted: %v", err)
			}
		})
	}
}
