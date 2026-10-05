package ratls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
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

	// SandboxID, when set, is the CRI pod sandbox ID the certificate's
	// sandbox-ID extension must carry (docs/ratls.md, "Sandbox identity").
	// Only [VerifyCert] can enforce it (the ID rides the certificate);
	// [VerifyAttestation] fails closed when it is set.
	SandboxID string

	// WorkloadName, when set, is the allowlist entry name the certificate's
	// matched-workload extension must carry (docs/ratls.md, "Matched
	// workload"). Like SandboxID it is CA-vouched: it is enforced only on the
	// chain-verified branch of the dual peer verifier, and VerifyAttestation /
	// VerifyCert fail closed when it is set — neither checks a CA chain, so
	// neither can authenticate the stamp.
	WorkloadName string

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

	// RequireCAEvidence selects the production trust mode for the dual CA /
	// RA-TLS peer verifier (dualVerifyPeerCallback). When false (default), a
	// peer whose leaf chains to a configured CA is accepted on the CA chain
	// alone (a sandbox-ID pin is still enforced) — the legacy/dev mode that
	// eases rolling upgrades and CA rotation. When true, a valid CA chain is no
	// longer sufficient: the leaf must ALSO carry re-verifiable RA-TLS evidence
	// (issuer.SignCSR copies the requester's nonce-free .1.1 extension onto the
	// leaf), which is re-verified per connection so a CA compromise or wrong
	// issuance policy is caught at the peer rather than trusted from the chain.
	// The embedded evidence is nonce-free by construction (bound to the leaf
	// key and claims, no per-connection nonce); connection liveness comes from
	// the TLS 1.3 proof-of-possession of the leaf key. Set by the production
	// profile; a self-signed RA-TLS peer is unaffected (it always verifies its
	// evidence via the fallback path).
	RequireCAEvidence bool
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
	if err := policy.checkEvidenceOnlyPins(); err != nil {
		return nil, err
	}
	return verifyOnline(att, pub, policy, nonce)
}

// VerifyCert verifies an RA-TLS certificate: it extracts the TEE attestation
// extension and verifies it against the cert's public key.
//
// Trust comes from the hardware attestation chain (AMD ARK → ASK → VCEK, or
// Intel equivalent for TDX) as verified by the same-TCB attestation-api, not
// from any certificate authority signature. A sandbox-ID pin therefore cannot
// be enforced here: the ID rests on CDS's signature over the leaf, which this
// path does not check (docs/ratls.md, "Sandbox identity").
//
// The certificate body is authenticated first (certutil.AuthenticateLeafBody):
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

	// Split out so a window failure keeps its own sentinel; callers
	// (dualVerifyPeerCallback, the mesh proxies) branch on ErrCertValidity.
	now := time.Now()
	if err := certutil.CheckValidity(cert, now); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertValidity, err)
	}
	// The classification is not actionable at this layer: both classes reach
	// here legitimately — the self-signed mesh peer, and (via
	// dualVerifyPeerCallback's RequireCAEvidence step) a CA-signed leaf whose
	// chain that caller has already verified. What the call buys is the
	// self-signature check on the self-issued case, which is the half of body
	// authentication this path would otherwise skip.
	if _, err := certutil.AuthenticateLeafBody(cert, now); err != nil {
		return nil, fmt.Errorf("ratls: peer certificate body: %w", err)
	}

	att, err := ExtractAttestation(cert)
	if err != nil {
		return nil, err
	}

	pub, err := publicKeyFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("ratls: extract public key: %w", err)
	}

	if err := policy.checkEvidenceOnlyPins(); err != nil {
		return nil, err
	}
	return verifyOnline(att, pub, policy, nonce)
}

// checkEvidenceOnlyPins rejects a policy the evidence alone cannot settle: the
// sandbox ID and the matched workload are CA-vouched stamps, and neither
// [VerifyAttestation] nor [VerifyCert] verifies a chain. It also requires the
// attestation-api, since there is no in-process verification path here.
func (p *VerifyPolicy) checkEvidenceOnlyPins() error {
	if p.AttestationApiURL == "" {
		return fmt.Errorf("%w: attestation-api URL is required", ErrInvalidReport)
	}
	if p.SandboxID != "" {
		return fmt.Errorf("%w: sandbox-ID pin requires a CA-verified certificate", ErrPolicyViolation)
	}
	if p.WorkloadName != "" {
		return fmt.Errorf("%w: workload pin requires a CA-verified certificate", ErrPolicyViolation)
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
// [agratls.VerifyWithService], which derives the REPORTDATA anchor from pub
// and nonce, fails closed on the verdict, and then enforces policy.Policy.
//
// C8s ships no in-process quote parser, so every platform is verified there,
// bare-metal SNP included; an inline VCEK travels in the envelope as
// collateral.
func verifyOnline(att *Attestation, pub crypto.PublicKey, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	expectedReportData, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("ratls: compute expected REPORTDATA: %w", err)
	}

	timeout := policy.AttestationVerifyTimeout
	if timeout <= 0 {
		timeout = defaultAttestationVerifyTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	svc := remote.NewClient(policy.AttestationApiURL)
	resp, err := agratls.VerifyWithService(ctx, svc, att, pub, nonce, policy.Policy)
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
		return fmt.Errorf("ratls: online %s attestation verify: %w", family, err)
	}
}

// publicKeyFromCert extracts and validates the public key from a certificate.
func publicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return nil, fmt.Errorf("ratls: unsupported ECDSA curve: %s", pub.Curve.Params().Name)
		}
		return pub, nil
	case ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("ratls: unsupported key type in certificate: %T", pub)
	}
}
