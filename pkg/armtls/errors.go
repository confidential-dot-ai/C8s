package armtls

import (
	"errors"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
)

// Sentinel errors for programmatic error handling via [errors.Is].
// These cover the verification pipeline stages — callers can distinguish
// between different failure modes without string matching.
var (
	// ErrKeyBinding indicates that the attestation report's REPORTDATA
	// does not match hash(publicKey), meaning the key was not generated
	// inside the claimed TEE.
	ErrKeyBinding = errors.New("armtls: REPORTDATA does not match key")

	// ErrSignatureInvalid indicates that the hardware attestation report's
	// signature could not be verified against the platform certificate chain
	// (e.g., AMD VCEK → ASK → ARK).
	ErrSignatureInvalid = errors.New("armtls: hardware signature verification failed")

	// ErrPolicyViolation indicates that the verified launch measurement is not
	// in the [VerifyPolicy] reference values. Debug and minimum-TCB policy are
	// enforced by the attestation-api; those rejections surface as the
	// attestation-api error or [ErrSignatureInvalid], not this sentinel.
	ErrPolicyViolation = errors.New("armtls: attestation policy check failed")

	// ErrCertValidity indicates the certificate is outside its validity
	// window: expired, or NotBefore further in the future than the shared
	// clock-skew allowance (certutil.LeafValiditySkew).
	ErrCertValidity = errors.New("armtls: certificate outside its validity window")

	// ErrNoAttestation indicates that a certificate does not contain the
	// ARmTLS attestation extension (OID 1.3.6.1.4.1.66378.1.1).
	ErrNoAttestation = agarmtls.ErrNoAttestation

	// ErrUnsupportedTEE indicates an unrecognized TEE platform type.
	ErrUnsupportedTEE = agarmtls.ErrUnsupportedTEE

	// ErrInvalidReport indicates a structurally invalid attestation report
	// (e.g., wrong size for the platform, truncated, or corrupt).
	ErrInvalidReport = agarmtls.ErrInvalidReport
)
