package guestverify

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

type recordingPolicy struct {
	calls int
	err   error
}

func (*recordingPolicy) platform() teetypes.PlatformType { return teetypes.PlatformTDX }
func (p *recordingPolicy) verifyEvidence(teetypes.AttestationEvidence, []byte, []byte) (*teetypes.VerificationResult, error) {
	p.calls++
	return nil, p.err
}
func (p *recordingPolicy) verifyCertificate(*x509.Certificate) error {
	p.calls++
	return p.err
}

func TestMeasuredPolicyCommonGates(t *testing.T) {
	p := &recordingPolicy{err: errors.New("platform verification refused")}
	for _, envelope := range []string{
		`{`,
		`{"platform":"snp","evidence":{}}`,
		`{"platform":"tdx"}`,
		`{"platform":"tdx","evidence":{"platform":"tdx","evidence":{}}}`,
	} {
		if _, err := verifyEvidence([]byte(envelope), nil, p); err == nil || errors.Is(err, p.err) {
			t.Fatalf("envelope %s must fail before platform verification: %v", envelope, err)
		}
	}
	if p.calls != 0 {
		t.Fatal("invalid envelopes reached platform verifier")
	}
	if _, err := verifyEvidence([]byte(tdxEnvelope), nil, p); !errors.Is(err, p.err) || p.calls != 1 {
		t.Fatalf("validated envelope did not propagate platform refusal: %v", err)
	}

	cert := attestedCert(t, teetypes.AttestationEvidence{Platform: "tdx"})
	cert.Signature[0] ^= 0xff
	if err := verifyServerCert(cert, p); err == nil || errors.Is(err, p.err) || p.calls != 1 {
		t.Fatalf("invalid certificate body reached platform verifier: %v", err)
	}
	cert.Signature[0] ^= 0xff
	if err := verifyServerCert(cert, p); !errors.Is(err, p.err) || p.calls != 2 {
		t.Fatalf("authenticated certificate did not propagate platform refusal: %v", err)
	}
}
