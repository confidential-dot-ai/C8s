package armtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// VerifyPolicy defines what attestation claims are acceptable.
type VerifyPolicy struct {
	// Native verifies evidence locally under a fixed native policy. When set,
	// AttestationApiURL is never consulted for verification.
	Native *NativeVerifier
	// Policy is the evidence policy the selected verifier enforces: image pins,
	// launch-measurement reference values, TDX runtime registers, the SEV-SNP
	// TCB floor and the debug rule. It must carry a launch measurement or an
	// image pin ([ErrUnpinned]). Leave ExpectedReportData unset — the
	// verifying paths derive it from the certificate key and refuse a value
	// that disagrees.
	Policy remote.Policy

	// RequireNonMigratable requires native SNP or TDX peers whose verified
	// launch policy forbids migration. Missing claims and unsupported platforms
	// fail closed. When false, migration is not checked.
	RequireNonMigratable bool

	// Nonce, when set, is verified against the attestation report's REPORTDATA.
	// REPORTDATA must equal hash(pubkey || nonce). Use when both sides agree on
	// a pre-shared nonce for additional freshness guarantees. If nil, no nonce
	// check is performed (TLS 1.3 already provides replay protection).
	Nonce []byte

	// ExtensionOID is the OID the evidence extension is carried under; unset
	// means [OIDARMTLSAttestation].
	ExtensionOID asn1.ObjectIdentifier

	// AttestationApiURL selects the legacy /verify service when Native is nil.
	// Native mode ignores this URL for verification and authenticates evidence
	// and collateral locally. One of these explicit verifier paths is required.
	//
	// SECURITY: the /verify response is currently not signed; the verifier
	// trusts whatever this URL returns. Operators MUST point this at an
	// attestation-api inside the same TCB (e.g. the node-local Unix socket
	// the DaemonSet's attest-proxy serves, or an in-guest loopback service).
	// A response-signing scheme would lift this constraint.
	AttestationApiURL string

	// AttestationVerifyTimeout bounds peer evidence verification.
	// If unset, a conservative default is used.
	AttestationVerifyTimeout time.Duration
}

// VerifyResult contains the verified attestation claims extracted from the cert.
type VerifyResult struct {
	// TEEType is the platform type.
	TEEType TEEType
	// ReportData is the 64-byte expected REPORTDATA that the verifier
	// confirmed the report is bound to (the result carries a match verdict,
	// not the report bytes, so this echoes the verified expectation).
	ReportData [64]byte
	// Measurement is the verified 48-byte launch measurement:
	// LAUNCH_DIGEST for SNP or MRTD for TDX.
	Measurement [48]byte
	// PlatformInfo contains verified platform metadata. Only set on SNP.
	PlatformInfo []byte
	// Verified is the selected verifier's result, which carries the platform
	// it verified and the claims it read. A caller holding it can enforce a
	// later policy against the same verdict without repeating verification.
	Verified remote.VerifyResponse
}

// VerifyAttestation authenticates a report's signature, collateral, debug and
// TCB policy through Native when configured, otherwise the legacy /verify API.
// It binds REPORTDATA to hash(pub || nonce) and enforces the caller's image pins.
// A policy that names no guest fails with [ErrUnpinned] before verification.
func VerifyAttestation(pub crypto.PublicKey, att *Attestation, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}
	if err := requirePins(policy.Policy); err != nil {
		return nil, err
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
//
// A policy that names no guest fails with [ErrUnpinned].
func VerifyCert(cert *x509.Certificate, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}
	if err := requirePins(policy.Policy); err != nil {
		return nil, err
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

	att, err := agarmtls.ExtractAttestation(cert, policy.extensionOID())
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

func (p *VerifyPolicy) extensionOID() asn1.ObjectIdentifier {
	if len(p.ExtensionOID) == 0 {
		return OIDARMTLSAttestation
	}
	return p.ExtensionOID
}

// requireAttestationApi requires an explicit native verifier or legacy URL.
func (p *VerifyPolicy) requireAttestationApi() error {
	if p.Native == nil && p.AttestationApiURL == "" {
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

// verifyOnline binds evidence to pub and nonce through the selected verifier,
// then enforces the caller's pins, including the anchored runtime replay rules.
// Native failures never fall back to the remote service.
func verifyOnline(
	att *Attestation,
	pub crypto.PublicKey,
	policy *VerifyPolicy,
	nonce []byte,
) (*VerifyResult, error) {
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

	pins := policy.Policy
	pins.Images = acceptReplayed(pins.Images)
	var resp remote.VerifyResponse
	if policy.Native != nil {
		anchor := expectedReportData[:sha512.Size384]
		if len(pins.ExpectedReportData) > 0 && !bytes.Equal(pins.ExpectedReportData, anchor) {
			return nil, fmt.Errorf("%w: configured report data does not bind the key", ErrInvalidReport)
		}
		pins.ExpectedReportData = anchor
		envelope, envelopeErr := att.Envelope()
		if envelopeErr != nil {
			return nil, envelopeErr
		}
		resp, err = policy.Native.VerifyEvidenceWithRuntimeLog(ctx, envelope, pins, att.RuntimeExtensions)
	} else {
		resp, err = agarmtls.VerifyWithService(ctx, NewAttestationClient(policy.AttestationApiURL), att, pub, nonce, pins)
	}
	if err != nil {
		return nil, mapVerifyError(att.Family, err)
	}
	if policy.RequireNonMigratable {
		if err := EnforceNonMigratable(&resp.Result); err != nil {
			return nil, err
		}
	}

	result := &VerifyResult{
		TEEType:    att.Family,
		ReportData: expectedReportData,
		Verified:   resp,
	}
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
// surface, which callers match with errors.Is. An attestation-api refusal of
// the evidence (400, 415, 422) is terminal and maps to [ErrInvalidReport];
// transport failures and every other status stay unwrapped, as retryable or as
// a deployment fault that is not the peer's.
func mapVerifyError(family TEEType, err error) error {
	var apiErr *remote.APIError
	switch {
	case errors.Is(err, remote.ErrSignatureInvalid):
		return ErrSignatureInvalid
	case errors.Is(err, remote.ErrReportDataMismatch):
		return fmt.Errorf("%w — key was not generated in this TEE", ErrKeyBinding)
	case errors.Is(err, remote.ErrMeasurementNotAllowed),
		errors.Is(err, remote.ErrRegistersNotAllowed),
		errors.Is(err, remote.ErrAnchorNotAllowed),
		errors.Is(err, remote.ErrLaunchFileNotAllowed),
		errors.Is(err, remote.ErrMinTcbNotAllowed),
		errors.Is(err, remote.ErrPCRNotAllowed),
		errors.Is(err, remote.ErrInitDataMismatch):
		return fmt.Errorf("%w: %v", ErrPolicyViolation, err)
	// ErrPlatformMismatch is the verifier answering for another platform than
	// the evidence named: a fault in its response, not a pin the peer failed,
	// so it stays unwrapped.
	case errors.Is(err, remote.ErrUnsupportedPlatform):
		return fmt.Errorf("%w: %v", ErrUnsupportedTEE, err)
	case errors.Is(err, remote.ErrInvalidLaunchDigest):
		return fmt.Errorf("%w: %v", ErrInvalidReport, err)
	// The api answers its own refusals in the JSON envelope; a non-JSON 4xx
	// comes from something in front of it and stays a deployment fault.
	case errors.As(err, &apiErr) && rejectsRequest(apiErr.Status):
		return fmt.Errorf("%w: attestation-api refused the evidence (%d): %w", ErrInvalidReport, apiErr.Status, err)
	default:
		return fmt.Errorf("armtls: online %s attestation verify: %w", family, err)
	}
}

// rejectsRequest reports whether a status names what was sent: the
// attestation-api answers evidence verdicts and body rejections with these
// alone. 401, 403 and 404 point at the deployment, not the peer, and so does
// 413, which an ingress body limit answers in JSON too.
func rejectsRequest(status int) bool {
	return status == http.StatusBadRequest ||
		status == http.StatusUnsupportedMediaType ||
		status == http.StatusUnprocessableEntity
}

// checkPeerKeyType accepts ECDSA P-256 or P-384 on either verification path.
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
