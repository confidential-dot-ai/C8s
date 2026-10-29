package armtls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// testMeasurement is the launch measurement a test pins so the evidence path
// reaches the check the test names rather than [ErrUnpinned].
var testMeasurement = bytes.Repeat([]byte{0x11}, SNPMeasurementSize)

// pinnedPolicy pins testMeasurement and verifies evidence through url.
func pinnedPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{AttestationApiURL: url, Policy: remote.Policy{Measurements: [][]byte{testMeasurement}}}
}

// pinnedStub is an attestation-api stub whose verdict reports testMeasurement,
// so pinnedPolicy admits the peer it answers for.
func pinnedStub(t *testing.T) *mockapi.Stub {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(testMeasurement)))
	return stub
}

// Every evidence path refuses a policy that names no guest: registers and a TCB
// floor narrow a guest a launch measurement or image pin already named, so on
// their own they admit any attested TEE.
func TestEvidencePathsRefuseAnUnpinnedPolicy(t *testing.T) {
	key, att, cert := testAttestedCert(t, nil)
	paths := map[string]func(*VerifyPolicy) error{
		"NewClientTLSConfig": func(policy *VerifyPolicy) error {
			_, _, err := NewClientTLSConfig(&ClientConfig{Policy: policy})
			return err
		},
		"NewServerTLSConfig": func(policy *VerifyPolicy) error {
			cfg := testServerConfig()
			cfg.ClientPolicy = policy
			_, _, err := NewServerTLSConfig(cfg)
			return err
		},
		"VerifyCert": func(policy *VerifyPolicy) error {
			_, err := VerifyCert(cert, policy, nil)
			return err
		},
		"VerifyAttestation": func(policy *VerifyPolicy) error {
			_, err := VerifyAttestation(&key.PublicKey, att, policy, nil)
			return err
		},
	}
	policies := map[string]*VerifyPolicy{
		"no pins": {AttestationApiURL: "http://unused.invalid"},
		"registers only": {
			AttestationApiURL: "http://unused.invalid",
			Policy:            remote.Policy{Registers: map[int][]byte{3: testMeasurement}},
		},
	}
	for path, call := range paths {
		for shape, policy := range policies {
			t.Run(path+" "+shape, func(t *testing.T) {
				if err := call(policy); !errors.Is(err, ErrUnpinned) {
					t.Fatalf("err = %v, want errors.Is ErrUnpinned", err)
				}
			})
		}
	}
}
