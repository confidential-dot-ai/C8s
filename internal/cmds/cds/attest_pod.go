package cds

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
