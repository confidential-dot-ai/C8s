// Package guestverify verifies a measured guest from the operator side: its
// fresh evidence and its armTLS serving certificate, both against one trust
// gate built from the image manifest, the launch key and the expected
// workload images. Verification runs in-process with attestation-go.
package guestverify

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// VerifyEnvelope verifies a self-describing evidence envelope in-process with
// attestation-go, the same engine `c8s verify` uses, so the operator flow
// needs no external verifier binary. A package var so tests can stub the
// verdict.
var VerifyEnvelope = teeverify.Verify

// platformVerifier is what the checks common to every platform hand a
// validated envelope or an authenticated certificate body to. [Policy]
// is the only production implementation; tests stub it to assert those common
// checks run first.
type platformVerifier interface {
	platform() teetypes.PlatformType
	verifyEvidence(env teetypes.AttestationEvidence, envelopeJSON, expectedReportData []byte) (*teetypes.VerificationResult, error)
	verifyCertificate(*x509.Certificate) error
}

// Policy is the trust gate for one manifest: the pinned image, the
// operator key the node must have been launched for, and the workload images
// its measurer was expected to extend, in first-extend order. The image
// identity carries its own family, so nothing here branches on a platform
// string.
type Policy struct {
	identity        runtimemeasure.ImageIdentity
	operatorPubPEM  []byte
	workloadDigests []string
	// policies are the allowlist policies the node measured after the
	// workloads, as the runtime extensions of its last verified cred-release
	// leaf; nil on SNP. checkIdentity accepts the list only as far as the
	// quote's register replays it.
	policies *policyList
}

// policyList holds the runtime extension list of the latest verified
// cred-release leaf, or of the fresh /attest response. The leaf's
// self-signature under its attested key covers the list, so the host cannot
// rewrite it.
type policyList struct {
	mu   sync.Mutex
	list []string
}

func (l *policyList) record(list []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = list
}

func (l *policyList) current() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.list
}

// Family is the TEE family the manifest pins.
func (exp Policy) Family() teetypes.Family {
	return exp.identity.Family()
}

// WithMeasuredPolicies returns exp tracking the node's measured allowlist
// policies, starting from list. Copies of the result share the list, so a
// verified armTLS leaf records its runtime extensions for later checks.
func (exp Policy) WithMeasuredPolicies(list []string) Policy {
	exp.policies = &policyList{list: list}
	return exp
}

// MeasuresPolicies reports whether exp tracks measured allowlist policies.
func (exp Policy) MeasuresPolicies() bool {
	return exp.policies != nil
}

// MeasuredPolicies is the list exp last recorded; nil when it tracks none.
func (exp Policy) MeasuredPolicies() []string {
	if exp.policies == nil {
		return nil
	}
	return exp.policies.current()
}

// platform is the bare-metal tag of the manifest's family. Cloud overlays are
// deliberately excluded: on az-*/gcp-* the launch-binding field is owned by the
// cloud stack, so it cannot carry the operator-key binding this gate reads.
func (exp Policy) platform() teetypes.PlatformType {
	return exp.identity.Family().DefaultPlatform()
}

// PolicyFor builds the trust gate from the operator's inputs: the image
// manifest (loaded atomically, its shape naming the platform), the operator
// public key PEM (the exact bytes the initrd hashed, so it must not be
// re-encoded), and the digest-pinned workload images the node's measurer is
// expected to have extended, in first-extend order. Tag references are
// rejected — only a canonical digest identifies an image.
func PolicyFor(manifestPath string, operatorPubPEM []byte, workloadImages []string) (Policy, error) {
	identity, err := runtimemeasure.LoadImageManifest(manifestPath)
	if err != nil {
		return Policy{}, fmt.Errorf("--image-manifest: %w", err)
	}
	if p := identity.Family().DefaultPlatform(); p == "" {
		return Policy{}, fmt.Errorf("--image-manifest: %s carries an image pin this flow has no gate for (family %q)", manifestPath, identity.Family())
	}
	digests, err := workloadChain(identity.Family(), workloadImages)
	if err != nil {
		return Policy{}, err
	}
	return Policy{identity: identity, operatorPubPEM: operatorPubPEM, workloadDigests: digests}, nil
}

// workloadChain canonicalizes --workload-image into the deduped, ordered
// digest set VerifyBinding folds onto the operator-key seed.
func workloadChain(family teetypes.Family, workloadImages []string) ([]string, error) {
	if len(workloadImages) == 0 {
		return nil, nil
	}
	// Accepting --workload-image off TDX would report an enforcement that
	// cannot exist, so refuse the flag instead of ignoring it.
	if family != teetypes.FamilyTDX {
		return nil, fmt.Errorf("--workload-image requires a TDX node: SEV-SNP has no runtime measurement register, so workload extends cannot be verified; rerun without it")
	}
	digests := make([]string, 0, len(workloadImages))
	seen := make(map[string]string, len(workloadImages))
	for _, ref := range workloadImages {
		d, err := runtimemeasure.CanonicalDigest(ref)
		if err != nil {
			return nil, fmt.Errorf("--workload-image: %w", err)
		}
		// The node's measurer extends a given image once, so a repeated ref
		// here extends the expected register one time too many and builds a
		// gate no node can satisfy. A repeat is a copy/paste slip, so report
		// it rather than dedup silently.
		if prev, dup := seen[d]; dup {
			return nil, fmt.Errorf("--workload-image %q and %q are the same image (%s): each expected image must be given once, in first-extend order, or the expected RTMR[3] chain can never match the node's", prev, ref, d)
		}
		seen[d] = ref
		digests = append(digests, d)
	}
	return digests, nil
}

// checkIdentity checks both halves of the measured identity against the claims
// attestation-go extracted from the signature-verified quote: the pinned image
// booted, and the node was launched for the operator's key and measured
// exactly these workloads. runtimemeasure resolves which field carries the
// binding (RTMR[3] on TDX, HOSTDATA on SNP) and how wide it is.
//
// workloadDigests is empty on SNP — it has no runtime-extend register, and
// workloadChain refuses --workload-image there — so the binding checked is the
// launch-committed HOSTDATA alone.
//
// A node that measures allowlist policies extends them after the workloads,
// and the list may run ahead of the quote, so any prefix that replays is
// accepted, under the rule runtimemeasure.MatchBindingPrefix applies at every
// c8s verifier. Policy and workload extends share one event encoding, so an
// extend after the workload chain passes whenever the node lists it as a
// policy: the workload chain itself stays exact.
func (exp Policy) checkIdentity(res *teetypes.VerificationResult) error {
	if err := exp.identity.Verify(res); err != nil {
		return err
	}
	err := runtimemeasure.VerifyBinding(res, exp.operatorPubPEM, exp.workloadDigests)
	if err == nil || exp.policies == nil {
		return err
	}
	policies := exp.policies.current()
	if len(policies) > armtls.MaxRuntimeExtensions {
		return fmt.Errorf("%w: %w: the node lists %d, over the per-boot cap of %d", err, ErrPoliciesDoNotReplay, len(policies), armtls.MaxRuntimeExtensions)
	}
	// One matcher for every c8s verifier: the workload chain then the
	// policies, all canonical, of which the register must carry at least the
	// whole workload chain.
	claimed := append(slices.Clone(exp.workloadDigests), policies...)
	k, perr := runtimemeasure.MatchBindingPrefix(res, exp.operatorPubPEM, claimed)
	if perr == nil && k >= len(exp.workloadDigests) {
		return nil
	}
	if perr == nil {
		return err
	}
	return fmt.Errorf("%w: %w: %v", err, ErrPoliciesDoNotReplay, perr)
}

// ErrPoliciesDoNotReplay marks a binding the node's measured-policy list
// does not account for.
var ErrPoliciesDoNotReplay = errors.New("no prefix of the node's measured policies replays it")

// VerifyEvidence verifies an evidence envelope bound to expectedReportData
// and enforces exp's measured identity on its claims.
func VerifyEvidence(envelopeJSON, expectedReportData []byte, exp Policy) (*teetypes.VerificationResult, error) {
	return verifyEvidence(envelopeJSON, expectedReportData, exp)
}

// verifyEvidence verifies an evidence envelope with attestation-go (HW chain +
// report_data binding) and enforces the full measured-identity policy on the
// verified claims. expectedReportData is what the quote must be bound to: the
// caller's nonce on the attest gate, the cert-key hash on the armTLS dial.
// Both paths funnel through here so the two gates cannot diverge. Fails
// closed on any missing piece.
func verifyEvidence(envelopeJSON, expectedReportData []byte, exp platformVerifier) (*teetypes.VerificationResult, error) {
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("parse evidence envelope: %w", err)
	}
	// The policy's platform comes from the manifest; the node must be that
	// platform. Bare-metal snp only: on az-snp/gcp-snp the HOSTDATA field is
	// owned by the cloud stack, so it cannot carry the operator-key binding.
	if env.Platform != exp.platform() {
		return nil, fmt.Errorf("node platform is %q but --image-manifest pins %q: credential release requires the node to be the platform the manifest describes", env.Platform, exp.platform())
	}
	if len(env.Evidence) == 0 {
		return nil, fmt.Errorf("evidence envelope carries no evidence object")
	}
	// The envelope is single-wrap: {platform, evidence:<platform object>}. A
	// double-wrapped envelope would reach the verifier as evidence whose
	// fields it ignores or misparses — refuse it loudly instead.
	var inner struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if json.Unmarshal(env.Evidence, &inner) == nil && inner.Platform != "" && len(inner.Evidence) > 0 {
		return nil, fmt.Errorf("evidence envelope is double-wrapped ({platform,evidence} inside evidence); the envelope must wrap the platform evidence object exactly once")
	}

	return exp.verifyEvidence(env, envelopeJSON, expectedReportData)
}

// verifyEvidence routes to the arm the manifest's family names. An unknown
// family cannot reach here — PolicyFor refuses one — but the default fails
// closed rather than falling through to another family's rules.
func (exp Policy) verifyEvidence(env teetypes.AttestationEvidence, envelopeJSON, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	switch exp.identity.Family() {
	case teetypes.FamilySNP:
		return exp.verifySNPEvidence(env, expectedReportData)
	case teetypes.FamilyTDX:
		return exp.verifyTDXEvidence(envelopeJSON, expectedReportData)
	default:
		return nil, fmt.Errorf("--image-manifest pins TEE family %q, which this flow has no gate for", exp.identity.Family())
	}
}

func (exp Policy) verifyTDXEvidence(envelopeJSON, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	res, err := VerifyEnvelope(envelopeJSON, teetypes.VerifyParams{
		ExpectedReportData: expectedReportData,
	})
	if err != nil {
		return nil, fmt.Errorf("verify evidence: %w", err)
	}
	// Defense in depth: a nil error already implies these, but never report a
	// success the result contradicts.
	if !res.SignatureValid {
		return nil, fmt.Errorf("quote signature invalid")
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return nil, fmt.Errorf("report_data does not match the expected binding (stale/replayed quote)")
	}
	if err := exp.checkIdentity(res); err != nil {
		return nil, err
	}
	return res, nil
}

// snpAttestTimeout bounds the gate's verification, whose collateral fetch
// (VCEK from AMD KDS) crosses the network.
const snpAttestTimeout = 30 * time.Second

// verifySNPEvidence verifies a bare-metal SNP envelope through localverify —
// which accepts the raw-report shape and pulls the VCEK from AMD KDS, rather
// than requiring the guest to have volunteered it inline — then enforces the
// same measured identity the armTLS dial does.
//
// The engine already enforces both pins (Measurements, ExpectedInitDataHash);
// checkIdentity re-checks them over the returned claims so a
// success the claims contradict is never accepted.
func (exp Policy) verifySNPEvidence(env teetypes.AttestationEvidence, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), snpAttestTimeout)
	defer cancel()
	res, err := VerifySNP(ctx, string(env.Platform), env.Evidence, exp.verificationParams(expectedReportData))
	if err != nil {
		return nil, fmt.Errorf("verify evidence: %w", err)
	}
	if !res.SignatureValid {
		return nil, fmt.Errorf("quote signature invalid")
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return nil, fmt.Errorf("report_data does not match the expected binding (stale/replayed quote)")
	}
	if err := exp.checkIdentity(res); err != nil {
		return nil, err
	}
	return res, nil
}

func (exp Policy) verificationParams(reportData []byte) localverify.Params {
	hostData := runtimemeasure.HostData(exp.operatorPubPEM)
	variants := exp.identity.LaunchDigests()
	measurements := make([][]byte, 0, len(variants))
	for _, v := range variants {
		measurements = append(measurements, append([]byte(nil), v.Digest[:]...))
	}
	return localverify.Params{
		Measurements:         measurements,
		ExpectedReportData:   reportData,
		ExpectedInitDataHash: hostData[:],
	}
}
