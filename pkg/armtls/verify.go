package armtls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// VerifyPolicy defines what attestation claims are acceptable.
type VerifyPolicy struct {
	// Policy is the evidence policy the attestation-api enforces: image pins,
	// launch-measurement reference values, TDX runtime registers, the SEV-SNP
	// TCB floor and the debug rule. Leave ExpectedReportData unset — the
	// verifying paths derive it from the certificate key and refuse a value
	// that disagrees.
	Policy remote.Policy

	// Nonce, when set, is verified against the attestation report's REPORTDATA.
	// REPORTDATA must equal hash(pubkey || nonce). Use when both sides agree on
	// a pre-shared nonce for additional freshness guarantees. If nil, no nonce
	// check is performed (TLS 1.3 already provides replay protection).
	Nonce []byte

	// AttestationApiURL is the attestation-api whose /verify endpoint performs
	// all evidence verification: hardware signature chain, REPORTDATA key
	// binding, debug policy, and minimum TCB. Required: there is no
	// in-process verification path; verification without it fails closed.
	//
	// SECURITY: the /verify response is currently not signed; the verifier
	// trusts whatever this URL returns. Operators MUST point this at an
	// attestation-api inside the same TCB (e.g. the node-local Unix socket
	// the DaemonSet's attest-proxy serves, or an in-guest loopback service).
	// A response-signing scheme would lift this constraint.
	AttestationApiURL string

	// AttestationVerifyTimeout bounds online attestation-api verification.
	// If unset, a conservative default is used.
	AttestationVerifyTimeout time.Duration
}

// VerifyResult contains the verified attestation claims extracted from the cert.
type VerifyResult struct {
	// TEEType is the platform type.
	TEEType TEEType
	// ReportData is the 64-byte expected REPORTDATA that the attestation-api
	// confirmed the report is bound to (the api returns only a match verdict,
	// not the report bytes, so this echoes the verified expectation).
	ReportData [64]byte
	// Measurement is the 48-byte launch measurement reported by the
	// attestation-api: LAUNCH_DIGEST for SNP or MRTD for TDX.
	Measurement [48]byte
	// PlatformInfo contains platform-specific metadata from the
	// attestation-api response. Only set on the SNP path.
	PlatformInfo []byte
}

// VerifyAttestation verifies a raw attestation report against a public key by
// forwarding the evidence to the attestation-api /verify endpoint
// (policy.AttestationApiURL, required):
//  1. The attestation-api verifies the hardware signature chain and that
//     REPORTDATA == hash(pub || nonce), proving the key was generated inside
//     the TEE (and the report is fresh if nonce is set), plus the debug and
//     minimum-TCB policy.
//  2. The launch measurement it returns is checked against policy.Policy here,
//     by the same enforcement every attestation-go caller gets.
func VerifyAttestation(pub crypto.PublicKey, att *Attestation, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}
	if err := policy.requireAttestationApi(); err != nil {
		return nil, err
	}
	return verifyOnline(att, pub, policy, nonce)
}

// VerifyCert verifies an armTLS certificate: it extracts the TEE attestation
// extension and verifies it against the cert's public key.
//
// Trust comes from the hardware attestation chain (AMD ARK → ASK → VCEK, or
// Intel equivalent for TDX) as verified by the same-TCB attestation-api, not
// from any certificate authority signature.
//
// The certificate body is authenticated first (requireSelfIssued):
// the validity window (NotBefore within [certutil.LeafValiditySkew], NotAfter
// with no allowance), because the embedded evidence carries no per-connection
// nonce and the window is the only freshness bound this path has; and, for a
// self-issued leaf, its signature under its own attested key, because the
// attestation binds only the key — every other field could otherwise be
// rewritten under a genuine extension. Doing it before the evidence
// round-trip also keeps a bad certificate from consuming an attestation-api
// call.
func VerifyCert(cert *x509.Certificate, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}

	// Split out so a window failure keeps its own sentinel, which callers
	// branch on (ErrCertValidity).
	now := time.Now()
	if err := certutil.CheckValidity(cert, now); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertValidity, err)
	}
	// This path verifies no chain, so the leaf must be self-issued: the
	// evidence binds the key alone. A CDS-issued leaf is verified on the
	// chain path (NewMeshClientTLSConfig).
	if err := requireSelfIssued(cert, now); err != nil {
		return nil, fmt.Errorf("armtls: peer certificate body: %w", err)
	}

	att, err := ExtractAttestation(cert)
	if err != nil {
		return nil, err
	}

	if err := checkPeerKeyType(cert); err != nil {
		return nil, err
	}

	if err := policy.requireAttestationApi(); err != nil {
		return nil, err
	}
	return verifyOnline(att, cert.PublicKey, policy, nonce)
}

// requireSelfIssued authenticates a certificate body the caller holds no chain
// for: the validity window and the self-signature under the certificate's own
// key.
func requireSelfIssued(cert *x509.Certificate, now time.Time) error {
	body, err := certutil.AuthenticateLeafBody(cert, now)
	if err != nil {
		return err
	}
	if body != certutil.BodySelfSigned {
		return fmt.Errorf("not self-issued: its body is %s", body)
	}
	return nil
}

// requireAttestationApi enforces the attestation-api URL every evidence path
// needs: there is no in-process verification path here.
func (p *VerifyPolicy) requireAttestationApi() error {
	if p.AttestationApiURL == "" {
		return fmt.Errorf("%w: attestation-api URL is required", ErrInvalidReport)
	}
	return nil
}

// CheckSandboxPin enforces expectedID against a leaf whose CA chain the caller
// has ALREADY verified. The ID is stamped by CDS into the signed area after it
// verifies the inventory-signed sandbox token, so the mesh CA signature — not
// the hardware evidence — is what authenticates it. Calling this on an
// unverified (e.g. self-signed) leaf would pin an attacker-chosen string.
//
// Empty expectedID is a no-op, so callers can invoke it unconditionally.
func CheckSandboxPin(cert *x509.Certificate, expectedID string) error {
	if expectedID == "" {
		return nil
	}
	id, err := SandboxIDFromCert(cert)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyViolation, err)
	}
	if id == "" {
		return fmt.Errorf("%w: sandbox-ID pin set but certificate carries no sandbox-ID extension", ErrPolicyViolation)
	}
	if id != expectedID {
		return fmt.Errorf("%w: certificate sandbox ID %q does not match pinned %q", ErrPolicyViolation, id, expectedID)
	}
	return nil
}

const defaultAttestationVerifyTimeout = 10 * time.Second

// verifyOnline hands the evidence to the attestation-api through
// [agarmtls.VerifyWithService], which derives the REPORTDATA anchor from pub
// and nonce, fails closed on the verdict, and then enforces policy.Policy.
//
// C8s ships no in-process quote parser, so every platform is verified there,
// bare-metal SNP included; an inline VCEK travels in the envelope as
// collateral.
func verifyOnline(att *Attestation, pub crypto.PublicKey, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	expectedReportData, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("armtls: compute expected REPORTDATA: %w", err)
	}

	timeout := policy.AttestationVerifyTimeout
	if timeout <= 0 {
		timeout = defaultAttestationVerifyTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	svc := remote.NewClient(policy.AttestationApiURL)
	resp, err := agarmtls.VerifyWithService(ctx, svc, att, pub, nonce, policy.Policy)
	if err != nil {
		return nil, mapVerifyError(att.Family, err)
	}

	result := &VerifyResult{TEEType: att.Family, ReportData: expectedReportData}
	if att.Family == TEETypeSEVSNP && len(resp.Result.Claims.PlatformData) > 0 {
		// The claims map came out of json.Unmarshal, so re-marshaling it
		// cannot fail.
		result.PlatformInfo, _ = json.Marshal(resp.Result.Claims.PlatformData)
	}
	if resp.Result.Claims.LaunchDigest != "" {
		// Hex validity and length were enforced by VerifyEvidence.
		measurement, _ := hex.DecodeString(resp.Result.Claims.LaunchDigest)
		copy(result.Measurement[:], measurement)
	}
	return result, nil
}

// mapVerifyError translates remote verdict sentinels onto this package's error
// surface, which callers match with errors.Is.
func mapVerifyError(family TEEType, err error) error {
	switch {
	case errors.Is(err, remote.ErrSignatureInvalid):
		return ErrSignatureInvalid
	case errors.Is(err, remote.ErrReportDataMismatch):
		return fmt.Errorf("%w — key was not generated in this TEE", ErrKeyBinding)
	case errors.Is(err, remote.ErrMeasurementNotAllowed), errors.Is(err, remote.ErrRegistersNotAllowed), errors.Is(err, remote.ErrAnchorNotAllowed):
		return fmt.Errorf("%w: %v", ErrPolicyViolation, err)
	case errors.Is(err, remote.ErrInvalidLaunchDigest):
		return fmt.Errorf("%w: %v", ErrInvalidReport, err)
	default:
		return fmt.Errorf("armtls: online %s attestation verify: %w", family, err)
	}
}

// checkPeerKeyType enforces the two key types a verifier accepts on either
// path (docs/armtls.md, "Key types").
func checkPeerKeyType(cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("armtls: peer key is %T, want ECDSA P-256 or P-384", cert.PublicKey)
	}
	if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
		return fmt.Errorf("armtls: peer key is ECDSA %s, want P-256 or P-384", pub.Curve.Params().Name)
	}
	return nil
}
