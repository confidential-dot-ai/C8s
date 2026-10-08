package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
)

// Both evidence paths require an attestation-api: there is no in-process verifier,
// so without one they must fail rather than accept unverified evidence.
func TestVerifyRequiresAttestationApi(t *testing.T) {
	if _, err := VerifyAttestation(nil, &Attestation{Family: TEETypeSEVSNP}, &VerifyPolicy{}, nil); err == nil {
		t.Fatal("VerifyAttestation ran with no attestation-api URL")
	} else if !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("err = %v, want ErrInvalidReport", err)
	}
}

// CheckSandboxPin is the one implementation both the mesh CA path and C8s
// verify use. Empty is a no-op so callers can invoke it unconditionally.
func TestCheckSandboxPin(t *testing.T) {
	withID, err := certWithSandboxID(t, "sandbox-abc")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSandboxPin(withID, ""); err != nil {
		t.Fatalf("empty pin should be a no-op: %v", err)
	}
	if err := CheckSandboxPin(withID, "sandbox-abc"); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	if err := CheckSandboxPin(withID, "other"); err == nil {
		t.Fatal("mismatched pin accepted")
	}
	if err := CheckSandboxPin(&x509.Certificate{}, "sandbox-abc"); err == nil {
		t.Fatal("pin satisfied by a certificate carrying no sandbox ID")
	}
}

func certWithSandboxID(t *testing.T, id string) (*x509.Certificate, error) {
	t.Helper()
	ext, err := MarshalSandboxIDExtension(id)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{Extensions: []pkix.Extension{ext}}, nil
}
