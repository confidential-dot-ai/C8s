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

	// ErrPolicyViolation indicates that the verified claims do not satisfy a
	// [VerifyPolicy] pin: launch measurement, TDX registers, image anchor,
	// vTPM PCR, init-data hash, verified platform, a TCB floor set for a
	// family that has none, or a sandbox or workload pin. Debug and TCB-floor
	// verdicts are the attestation-api's; it refuses them with a 4xx, which
	// surfaces as [ErrInvalidReport].
	ErrPolicyViolation = errors.New("armtls: attestation policy check failed")

	// ErrCertValidity indicates the certificate is outside its validity
	// window: expired, or NotBefore further in the future than the shared
	// clock-skew allowance (certutil.LeafValiditySkew).
	ErrCertValidity = errors.New("armtls: certificate outside its validity window")

	// ErrNoAttestation indicates that a certificate does not contain the
	// armTLS attestation extension (OID 1.3.6.1.4.1.66378.1.1).
	ErrNoAttestation = agarmtls.ErrNoAttestation

	// ErrUnsupportedTEE indicates an unrecognized TEE platform type.
	ErrUnsupportedTEE = agarmtls.ErrUnsupportedTEE

	// ErrInvalidReport indicates a structurally invalid attestation report
	// (e.g., wrong size for the platform, truncated, or corrupt), or evidence
	// the attestation-api refused with 400, 413, 415 or 422. Either is
	// terminal: resending the same evidence cannot succeed. Its refusals do not
	// say which check failed, so they cannot claim [ErrPolicyViolation].
	ErrInvalidReport = agarmtls.ErrInvalidReport
)
