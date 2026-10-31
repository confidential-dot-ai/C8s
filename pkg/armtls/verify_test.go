package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// Both evidence paths require an attestation-api: there is no in-process verifier,
// so without one they must fail rather than accept unverified evidence.
func TestVerifyRequiresAttestationApi(t *testing.T) {
	if _, err := VerifyAttestation(nil, &Attestation{Family: TEETypeSEVSNP}, pinnedPolicy(""), nil); err == nil {
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

// A guest image is its launch digest plus the registers its platform measures
// into, which is one table every pin path reads.
func TestImageRegistersIdentifyAGuestImage(t *testing.T) {
	if registers, identified := ImageRegisters(teetypes.FamilyTDX); !identified || !slices.Equal(registers, []int{1, 2}) {
		t.Fatalf("TDX registers = %v (identified %v), want RTMR[1] and RTMR[2]", registers, identified)
	}
	if registers, identified := ImageRegisters(teetypes.FamilySNP); !identified || len(registers) != 0 {
		t.Fatalf("SEV-SNP registers = %v (identified %v), want none", registers, identified)
	}
	if _, identified := ImageRegisters(teetypes.FamilyUnknown); identified {
		t.Fatal("a family with no verification rules identifies a guest image")
	}
}
