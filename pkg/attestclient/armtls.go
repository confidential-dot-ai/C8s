package attestclient

import (
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// MakeSNPARMTLSAttestFunc returns an ARmTLS AttestFunc (matching
// pkg/armtls.ServerConfig.AttestFunc) that asks an attestation-api for
// an SEV-SNP report binding the serving key. customData is the hex-encoded
// REPORTDATA the armtls TLS handshake passes in; only the leading SHA-384
// bytes are sent to the service to match the SNP report layout.
//
// The name says SNP but the body is platform-agnostic — ARMTLSEvidence
// dispatches on resp.Platform. TDX guests use it too; the SNP-shaped
// truncation to 48 bytes is harmless for TDX because ReportDataForKey
// zero-pads its 48-byte SHA-384 hash to the 64-byte REPORTDATA field.
func MakeSNPARMTLSAttestFunc(client Client, attestationApiURL string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, customData string) (string, error) {
		reportDataBytes, err := hex.DecodeString(customData)
		if err != nil {
			return "", fmt.Errorf("decode report data hex: %w", err)
		}
		reportDataBytes = reportDataBytes[:sha512.Size384]
		resp, err := client.GenerateEvidenceContext(ctx, attestationApiURL, reportDataBytes)
		if err != nil {
			return "", fmt.Errorf("attestation-api: %w", err)
		}
		return ARMTLSEvidence(resp)
	}
}

// AttestationExtension builds a nonce-free ARmTLS attestation extension
// binding pub via the local attestation-api, for embedding in a CSR
// (docs/armtls.md). CDS copies the extension onto the issued leaf, which is how
// a workload leaf carries hardware evidence a verifier can re-check — the same
// embed the mesh client uses for its own leaf
// (cdsclient.attestationExtension). It is nonce-free by design: the serving
// cert carries no per-request nonce, so [armtls.VerifyCert] recomputes the
// anchor with nonce=nil.
func (c Client) AttestationExtension(ctx context.Context, attestationApiURL string, pub crypto.PublicKey) (pkix.Extension, error) {
	reportData, err := agarmtls.ReportDataForKey(pub, nil)
	if err != nil {
		return pkix.Extension{}, err
	}
	resp, err := c.GenerateEvidenceContext(ctx, attestationApiURL, reportData[:sha512.Size384])
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("attestation-api: %w", err)
	}
	att, err := agarmtls.NewAttestation(evidenceEnvelope(resp))
	if err != nil {
		return pkix.Extension{}, err
	}
	return armtls.MarshalExtension(att)
}

// ARMTLSEvidence returns the payload to embed in an ARmTLS certificate
// extension: the raw report for native SEV-SNP (snp, gcp-snp), the evidence
// envelope for everything else. See attestation-go/armtls.EvidenceForExtension
// for why the two shapes exist and what native TDX loses on the way in.
func ARMTLSEvidence(resp remote.AttestResponse) (string, error) {
	evidence, err := agarmtls.EvidenceForExtension(evidenceEnvelope(resp))
	if err != nil {
		return "", err
	}
	return string(evidence), nil
}

// evidenceEnvelope re-tags an /attest response as the library's evidence
// envelope. The two carry the same JSON; only the platform tag's Go type
// differs.
func evidenceEnvelope(resp remote.AttestResponse) teetypes.AttestationEvidence {
	return teetypes.AttestationEvidence{
		Platform: teetypes.NormalizePlatform(string(resp.Platform)),
		Evidence: resp.Evidence,
	}
}
