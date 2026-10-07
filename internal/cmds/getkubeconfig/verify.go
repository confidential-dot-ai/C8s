// Package getkubeconfig implements the operator-side client (B4 client) that
// obtains a kube credential from a measured CVM: it attests the node,
// confirms the full measured identity — on TDX the image tuple (MRTD,
// RTMR[1], RTMR[2]) plus the RTMR[3] chain seeded by the operator's key and
// extended by the expected workload images; on SEV-SNP the pinned per-SMP
// launch digest plus the operator-key HOSTDATA binding — then exchanges a CSR
// for a short-lived kube client cert over the cred-release endpoint and
// assembles a kubeconfig.
package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
)

// verifyEnvelope verifies a self-describing evidence envelope in-process with
// attestation-go, the same engine `c8s verify` uses, so the operator flow
// needs no external verifier binary. A package var so tests can stub the
// verdict.
var verifyEnvelope = teeverify.Verify

// platformVerifier is what the checks common to every platform hand a
// validated envelope or an authenticated certificate body to. [measuredPolicy]
// is the only production implementation; tests stub it to assert those common
// checks run first.
type platformVerifier interface {
	platform() teetypes.PlatformType
	verifyEvidence(env teetypes.AttestationEvidence, envelopeJSON, expectedReportData []byte) (*teetypes.VerificationResult, error)
	verifyCertificate(*x509.Certificate) error
}

// measuredPolicy is the trust gate for one manifest: the pinned image, the
// operator key the node must have been launched for, and the workload images
// its measurer was expected to extend, in first-extend order. The image
// identity carries its own family, so nothing here branches on a platform
// string.
type measuredPolicy struct {
	identity        runtimemeasure.ImageIdentity
	operatorPubPEM  []byte
	workloadDigests []string
}

// platform is the bare-metal tag of the manifest's family. Cloud overlays are
// deliberately excluded: on az-*/gcp-* the launch-binding field is owned by the
// cloud stack, so it cannot carry the operator-key binding this gate reads.
func (exp measuredPolicy) platform() teetypes.PlatformType {
	return exp.identity.Family().DefaultPlatform()
}

// policyFor builds the trust gate from the operator's inputs: the image
// manifest (loaded atomically, its shape naming the platform), the operator
// public key PEM (the exact bytes the initrd hashed, so it must not be
// re-encoded), and the digest-pinned workload images the node's measurer is
// expected to have extended, in first-extend order. Tag references are
// rejected — only a canonical digest identifies an image.
func policyFor(manifestPath string, operatorPubPEM []byte, workloadImages []string) (measuredPolicy, error) {
	identity, err := runtimemeasure.LoadImageManifest(manifestPath)
	if err != nil {
		return measuredPolicy{}, fmt.Errorf("--image-manifest: %w", err)
	}
	if p := identity.Family().DefaultPlatform(); p == "" {
		return measuredPolicy{}, fmt.Errorf("--image-manifest: %s carries an image pin this flow has no gate for (family %q)", manifestPath, identity.Family())
	}
	digests, err := workloadChain(identity.Family(), workloadImages)
	if err != nil {
		return measuredPolicy{}, err
	}
	return measuredPolicy{identity: identity, operatorPubPEM: operatorPubPEM, workloadDigests: digests}, nil
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
func (exp measuredPolicy) checkIdentity(res *teetypes.VerificationResult) error {
	if err := exp.identity.Verify(res); err != nil {
		return err
	}
	return runtimemeasure.VerifyBinding(res, exp.operatorPubPEM, exp.workloadDigests)
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
// family cannot reach here — policyFor refuses one — but the default fails
// closed rather than falling through to another family's rules.
func (exp measuredPolicy) verifyEvidence(env teetypes.AttestationEvidence, envelopeJSON, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	switch exp.identity.Family() {
	case teetypes.FamilySNP:
		return exp.verifySNPEvidence(env, expectedReportData)
	case teetypes.FamilyTDX:
		return exp.verifyTDXEvidence(envelopeJSON, expectedReportData)
	default:
		return nil, fmt.Errorf("--image-manifest pins TEE family %q, which this flow has no gate for", exp.identity.Family())
	}
}

func (exp measuredPolicy) verifyTDXEvidence(envelopeJSON, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	res, err := verifyEnvelope(envelopeJSON, teetypes.VerifyParams{
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

// attestAndVerify fetches a nonce-bound quote from the guest's
// attestation-api, verifies it in-process (HW chain + report_data freshness),
// and enforces the full measured-identity policy. It proves: genuine TDX +
// the pinned guest image booted + the node trusts the operator's key and ran
// exactly the expected workload extends. Returns nil on success.
func attestAndVerify(ctx context.Context, attestURL string, exp platformVerifier) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	evidence, err := postAttest(ctx, attestURL, nonce)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	_, err = verifyEvidence(evidence, nonce, exp)
	return err
}

// postAttest sends the nonce to POST /attest and returns the raw evidence body
// (the self-describing {platform, evidence} envelope attestation-go consumes).
//
// report_data goes to /attest base64-encoded (what the attestation-api
// decodes); attestation-go compares the same raw bytes. Matches confai's
// verify.
func postAttest(ctx context.Context, attestURL string, nonce []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"platform":    "auto",
		"report_data": base64.StdEncoding.EncodeToString(nonce),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return readAttestationResponse(http.DefaultClient, req)
}

// readAttestationResponse bounds the evidence envelope on both bootstrap paths.
func readAttestationResponse(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		const maxErrorBody = 1024
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody+1))
		if err != nil {
			return nil, err
		}
		suffix := ""
		if len(respBody) > maxErrorBody {
			respBody = respBody[:maxErrorBody]
			suffix = "... (truncated)"
		}
		return nil, fmt.Errorf("attest HTTP %d: %s%s", resp.StatusCode, respBody, suffix)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(respBody) > 8<<20 {
		return nil, fmt.Errorf("attestation response exceeds 8 MiB")
	}
	return respBody, nil
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
func (exp measuredPolicy) verifySNPEvidence(env teetypes.AttestationEvidence, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), snpAttestTimeout)
	defer cancel()
	res, err := verifySNPARMTLS(ctx, string(env.Platform), env.Evidence, exp.verificationParams(expectedReportData))
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

func (exp measuredPolicy) verificationParams(reportData []byte) localverify.Params {
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
