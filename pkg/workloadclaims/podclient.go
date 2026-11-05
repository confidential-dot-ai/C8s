package workloadclaims

import (
	"context"
	"crypto"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ObtainPodCertificateContext is the guest-only issuance profile. The caller
// owns a complete admission snapshot and exclusive access to the local quote
// service; neither access nor this request is delegated to a Pod container.
// The round is the node's (attestclient.IssuanceProfile); what differs is the
// binding, PodReportData over the canonical claims, and that the claims
// travel in the request instead of a sandbox token.
func ObtainPodCertificateContext(ctx context.Context, c attestclient.Client, attestationURL, csrPEM string, claims PodClaims) (attestclient.CertificateResult, error) {
	canonical, err := claims.Canonical()
	if err != nil {
		return attestclient.CertificateResult{}, err
	}
	challenge, err := c.AuthenticateContext(ctx)
	if err != nil {
		return attestclient.CertificateResult{}, fmt.Errorf("authenticate Pod: %w", err)
	}
	result, err := c.ObtainCertificateWithProfileContext(ctx, attestationURL, csrPEM, challenge.Challenge, attestclient.IssuanceProfile{
		ReportData: func(key crypto.PublicKey, nonce []byte) ([]byte, error) {
			return PodReportData(key, nonce, canonical)
		},
		Request: func(platform teetypes.PlatformType, req *types.AttestRequestBody) error {
			if !platform.IsTDX() {
				return fmt.Errorf("pod credentials require TDX evidence")
			}
			req.PodClaims = canonical
			return nil
		},
	})
	if err != nil {
		return attestclient.CertificateResult{}, err
	}
	result.RuntimeExtensions = claims.RuntimeExtensions
	return result, nil
}
