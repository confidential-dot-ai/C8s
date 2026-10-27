package workloadclaims

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ObtainPodCertificateContext is the guest-only issuance profile. The caller
// owns a complete admission snapshot and exclusive access to the local quote
// service; neither access nor this request is delegated to a Pod container.
func ObtainPodCertificateContext(ctx context.Context, c attestclient.Client, attestationURL, csrPEM string, claims PodClaims) (attestclient.CertificateResult, error) {
	canonical, err := claims.Canonical()
	if err != nil {
		return attestclient.CertificateResult{}, err
	}
	csr, err := attestation.ParseAndVerifyCSR(csrPEM)
	if err != nil {
		return attestclient.CertificateResult{}, err
	}
	challenge, err := c.AuthenticateContext(ctx)
	if err != nil {
		return attestclient.CertificateResult{}, fmt.Errorf("authenticate Pod: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return attestclient.CertificateResult{}, fmt.Errorf("invalid Pod challenge")
	}
	report, err := PodReportData(csr.PublicKey, nonce, canonical)
	if err != nil {
		return attestclient.CertificateResult{}, err
	}
	evidence, err := c.GenerateEvidenceContext(ctx, attestationURL, report)
	if err != nil {
		return attestclient.CertificateResult{}, fmt.Errorf("attest Pod: %w", err)
	}
	if !evidence.Platform.IsTDX() {
		return attestclient.CertificateResult{}, fmt.Errorf("pod credentials require TDX evidence")
	}
	cert, err := c.AttestContext(ctx, types.AttestRequestBody{
		Challenge: challenge.Challenge, Evidence: evidence.Envelope(), CSR: csrPEM, PodClaims: canonical,
	})
	if err != nil {
		return attestclient.CertificateResult{}, err
	}
	return attestclient.CertificateResult{Certificate: cert, Challenge: challenge.Challenge, Platform: evidence.Platform, Evidence: evidence.Evidence, RuntimeExtensions: claims.RuntimeExtensions}, nil
}
