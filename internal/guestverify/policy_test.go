package guestverify

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// recordingGate stands in for a family's half of the gate, so the tests can
// assert the common checks run before it.
type recordingGate struct {
	calls int
	err   error
}

func (*recordingGate) hasRuntimeRegister() bool { return true }
func (g *recordingGate) verifyEvidence(Policy, teetypes.AttestationEvidence, []byte, []byte) (*teetypes.VerificationResult, error) {
	g.calls++
	return nil, g.err
}
func (g *recordingGate) verifyCertificate(Policy, *x509.Certificate) error {
	g.calls++
	return g.err
}

// An unknown family gets no gate, which is why PolicyFor refuses one and the
// per-family arms need no fallback.
func TestUnknownFamilyHasNoGate(t *testing.T) {
	if gate := gateFor(teetypes.FamilyUnknown); gate != nil {
		t.Fatalf("gateFor(unknown) = %T, want no gate", gate)
	}
}

func TestMeasuredPolicyCommonGates(t *testing.T) {
	p := &recordingGate{err: errors.New("platform verification refused")}
	exp := testPolicy(t, operatorPub(t))
	exp.gate = p
	for _, envelope := range []string{
		`{`,
		`{"platform":"snp","evidence":{}}`,
		`{"platform":"tdx"}`,
		`{"platform":"tdx","evidence":{"platform":"tdx","evidence":{}}}`,
	} {
		if _, err := verifyEvidence([]byte(envelope), nil, exp); err == nil || errors.Is(err, p.err) {
			t.Fatalf("envelope %s must fail before platform verification: %v", envelope, err)
		}
	}
	if p.calls != 0 {
		t.Fatal("invalid envelopes reached platform verifier")
	}
	if _, err := verifyEvidence([]byte(tdxEnvelope), nil, exp); !errors.Is(err, p.err) || p.calls != 1 {
		t.Fatalf("validated envelope did not propagate platform refusal: %v", err)
	}

	cert := attestedCert(t, teetypes.AttestationEvidence{Platform: "tdx"})
	cert.Signature[0] ^= 0xff
	if err := verifyServerCert(cert, exp); err == nil || errors.Is(err, p.err) || p.calls != 1 {
		t.Fatalf("invalid certificate body reached platform verifier: %v", err)
	}
	cert.Signature[0] ^= 0xff
	if err := verifyServerCert(cert, exp); !errors.Is(err, p.err) || p.calls != 2 {
		t.Fatalf("authenticated certificate did not propagate platform refusal: %v", err)
	}
}
