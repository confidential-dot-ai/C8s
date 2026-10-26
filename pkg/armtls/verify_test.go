package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
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

// An evidence refusal is terminal; other statuses and transport failures
// must not carry a terminal sentinel.
func TestMapVerifyError(t *testing.T) {
	sentinels := []error{ErrSignatureInvalid, ErrKeyBinding, ErrPolicyViolation, ErrInvalidReport, ErrUnsupportedTEE}
	tests := []struct {
		name string
		err  error
		want error // nil: no sentinel
	}{
		{"signature invalid", remote.ErrSignatureInvalid, ErrSignatureInvalid},
		{"report data mismatch", remote.ErrReportDataMismatch, ErrKeyBinding},
		{"measurement not allowed", remote.ErrMeasurementNotAllowed, ErrPolicyViolation},
		{"registers not allowed", remote.ErrRegistersNotAllowed, ErrPolicyViolation},
		{"anchor not allowed", remote.ErrAnchorNotAllowed, ErrPolicyViolation},
		{"min TCB not allowed", remote.ErrMinTcbNotAllowed, ErrPolicyViolation},
		{"PCR not allowed", remote.ErrPCRNotAllowed, ErrPolicyViolation},
		{"init data mismatch", remote.ErrInitDataMismatch, ErrPolicyViolation},
		{"platform mismatch", remote.ErrPlatformMismatch, ErrPolicyViolation},
		{"unsupported platform", remote.ErrUnsupportedPlatform, ErrUnsupportedTEE},
		{"invalid launch digest", remote.ErrInvalidLaunchDigest, ErrInvalidReport},
		{"api 400", &remote.APIError{Status: 400}, ErrInvalidReport},
		{"api 422", &remote.APIError{Status: 422}, ErrInvalidReport},
		{"wrapped api 422", fmt.Errorf("verify: %w", &remote.APIError{Status: 422}), ErrInvalidReport},
		{"api 413", &remote.APIError{Status: 413}, nil},
		{"api 415", &remote.APIError{Status: 415}, ErrInvalidReport},
		{"api 401", &remote.APIError{Status: 401}, nil},
		{"api 403", &remote.APIError{Status: 403}, nil},
		{"api 404", &remote.APIError{Status: 404}, nil},
		{"api 405", &remote.APIError{Status: 405}, nil},
		{"api 408", &remote.APIError{Status: 408}, nil},
		{"api 429", &remote.APIError{Status: 429}, nil},
		{"api 503", &remote.APIError{Status: 503}, nil},
		{"unexpected 422 with body", &remote.UnexpectedError{Status: 422, Text: "bad json"}, nil},
		{"unexpected 415 with body", &remote.UnexpectedError{Status: 415, Text: "unsupported"}, nil},
		{"unexpected 400 without body", &remote.UnexpectedError{Status: 400}, nil},
		{"unexpected 404 with body", &remote.UnexpectedError{Status: 404, Text: "not found"}, nil},
		{"unexpected 502 with body", &remote.UnexpectedError{Status: 502, Text: "bad gateway"}, nil},
		{"transport", &remote.RequestError{Err: errors.New("connection refused")}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapVerifyError(TEETypeTDX, tc.err)
			for _, s := range sentinels {
				if is := errors.Is(got, s); is != (s == tc.want) {
					t.Errorf("errors.Is(mapVerifyError(%v), %v) = %t, want %t", tc.err, s, is, !is)
				}
			}
			// Response and transport errors stay reachable for errors.As.
			if !isRemoteSentinel(tc.err) && !errors.Is(got, tc.err) {
				t.Errorf("mapVerifyError(%v) = %v, want it to wrap the original error", tc.err, got)
			}
		})
	}
}

func isRemoteSentinel(err error) bool {
	for _, s := range []error{remote.ErrSignatureInvalid, remote.ErrReportDataMismatch, remote.ErrMeasurementNotAllowed, remote.ErrRegistersNotAllowed, remote.ErrAnchorNotAllowed, remote.ErrInvalidLaunchDigest,
		remote.ErrMinTcbNotAllowed, remote.ErrPCRNotAllowed, remote.ErrInitDataMismatch, remote.ErrPlatformMismatch, remote.ErrUnsupportedPlatform} {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}
