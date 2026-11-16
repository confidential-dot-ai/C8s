package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// podProfileRefusal names why a request carrying pod claims is not a Pod
// attestation, or is empty when it is one. The response stays opaque; the
// cause is for the server log.
func (h AttestHandler) podProfileRefusal(req types.AttestRequestBody, fields map[string]json.RawMessage, csr *x509.CertificateRequest, claimErr error) string {
	switch {
	case claimErr != nil:
		return fmt.Sprintf("pod claims: %v", claimErr)
	case len(req.SandboxToken) != 0:
		return "a sandbox token accompanies the pod claims"
	case fields["runtime_extensions"] != nil:
		return "runtime_extensions accompany the pod claims"
	case !req.Evidence.Platform.IsTDX():
		return "evidence is not from TDX"
	case len(h.PodImages) == 0:
		return "no pod image policy is configured"
	case len(csr.Extensions) != 0:
		return "the CSR carries extensions"
	case csr.Subject.String() != "":
		return "the CSR carries a subject"
	}
	return ""
}

// enforcePodImages requires one whole image/key tuple AND exact replay of the
// complete journal. Prefix acceptance alone cannot authenticate a complete
// observation history: unextended records must never earn a workload stamp.
func enforcePodImages(resp remote.VerifyResponse, pins []remote.ImagePin, platform teetypes.PlatformType, log []string) error {
	if !platform.IsTDX() || !resp.Result.Platform.IsTDX() || len(pins) == 0 {
		return fmt.Errorf("pod image policy unavailable")
	}
	for _, pin := range pins {
		if len(pin.Anchor) == 0 || len(pin.Registers[1]) != 48 || len(pin.Registers[2]) != 48 {
			continue
		}
		if armtls.EnforceImages(resp, []remote.ImagePin{pin}, platform, log) != nil {
			continue
		}
		if runtimemeasure.VerifyBinding(&resp.Result, pin.Anchor, log) == nil {
			return nil
		}
	}
	return fmt.Errorf("pod image, launch key or complete runtime journal not allowed")
}

// resolvePodWorkload admits a pod CVM's complete image journal against one
// atomic policy snapshot: every measured digest must be in the current
// workload policy. When the pod's whole observation set (images, argv,
// environment and mounts, as the quote-bound claims carry them) matches
// exactly one entry of that snapshot, the leaf names it; otherwise the pod
// gets the unnamed membership leaf.
func (h AttestHandler) resolvePodWorkload(ctx context.Context, pod workloadclaims.PodClaims) (*armtls.MatchedWorkload, error) {
	if h.AllowlistStore == nil {
		return nil, fmt.Errorf("pod issuance requires an allowlist")
	}
	snapshot, err := h.policySnapshot()
	if err != nil {
		return nil, err
	}
	membership := make(map[string]struct{}, len(pod.RuntimeExtensions))
	for _, d := range pod.RuntimeExtensions {
		if !snapshot.Contains(d) {
			return nil, fmt.Errorf("pod image membership not authorized")
		}
		membership[d] = struct{}{}
	}
	resp := workloadclaims.SandboxDigestsResponse{Digests: pod.RuntimeExtensions, Containers: pod.Containers}
	return h.matchWorkload(ctx, snapshot, resp, membership, workloadclaims.VerifiedSandbox{SandboxID: pod.InstanceID()}), nil
}

// podIssuance is the Pod CVM profile: the quote binds the pod claims, and the
// claims carry the identity the leaf states.
type podIssuance struct {
	h          AttestHandler
	req        types.AttestRequestBody
	claims     workloadclaims.PodClaims
	remoteAddr string
}

// bind refuses a CSR key the node profile would refuse, then binds the
// evidence to the pod claims, the key and the challenge together. The sandbox
// is the pod instance.
func (p podIssuance) bind(ctx context.Context, w http.ResponseWriter, csrPub *ecdsa.PublicKey, challenge []byte) ([64]byte, workloadclaims.VerifiedSandbox, bool) {
	sandbox := workloadclaims.VerifiedSandbox{SandboxID: p.claims.InstanceID()}
	if _, err := armtls.ReportDataForKey(csrPub, challenge); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return [64]byte{}, sandbox, false
	}
	bound, err := workloadclaims.PodReportData(csrPub, challenge, p.req.PodClaims)
	if err != nil {
		slog.Warn("Pod attestation profile refused", "reason", err, "remote_addr", p.remoteAddr)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, "Pod attestation profile not authorized")
		return [64]byte{}, sandbox, false
	}
	var reportData [64]byte
	copy(reportData[:], bound)
	return reportData, sandbox, true
}

func (p podIssuance) admitImage(w http.ResponseWriter, verified remote.VerifyResponse, launchDigest string) bool {
	if err := enforcePodImages(verified, p.h.PodImages, p.req.Evidence.Platform, p.claims.RuntimeExtensions); err != nil {
		slog.Warn("Pod identity does not match policy", "launch_digest", launchDigest, "error", err, "remote_addr", p.remoteAddr)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied, "Pod identity not allowed")
		return false
	}
	return true
}

// resolveWorkload reports no router: the router role comes from the inventory
// containers view, which a Pod CVM is not served by.
func (p podIssuance) resolveWorkload(ctx context.Context, _ workloadclaims.VerifiedSandbox) (*armtls.MatchedWorkload, bool, error) {
	matched, err := p.h.resolvePodWorkload(ctx, p.claims)
	return matched, false, err
}

// clientDocument states what the claims carry: a digest that is not hex stamps
// the prefix that decoded.
func (p podIssuance) clientDocument() ([]byte, string) {
	if p.claims.ClientDocumentDigest == "" {
		return nil, ""
	}
	stamped, _ := hex.DecodeString(p.claims.ClientDocumentDigest)
	return stamped, p.claims.ClientDocumentDigest
}

// A Pod identity binds no node inventory.
func (p podIssuance) recordIssued(workloadclaims.VerifiedSandbox) {}
