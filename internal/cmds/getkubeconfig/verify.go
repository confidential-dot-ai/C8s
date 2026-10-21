// Package getkubeconfig implements the operator-side client (B4 client) that
// obtains a kube credential from a measured CVM: it attests the node,
// confirms the full measured identity — on TDX the image tuple (MRTD,
// RTMR[1], RTMR[2]) plus the RTMR[3] chain seeded by the operator's key and
// extended by the expected workload images, then the node's measured
// allowlist policies; on SEV-SNP the pinned per-SMP
// launch digest plus the operator-key HOSTDATA binding — then exchanges a CSR
// for a short-lived kube client cert over the cred-release endpoint and
// assembles a kubeconfig.
package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/guestverify"
)

// attestAndVerify fetches a nonce-bound quote from the guest's
// attestation-api, verifies it in-process (HW chain + report_data freshness),
// and enforces the full measured-identity policy. It proves: genuine TDX +
// the pinned guest image booted + the node trusts the operator's key and ran
// exactly the expected workload extends. Returns nil on success.
func attestAndVerify(ctx context.Context, attestURL string, exp guestverify.Policy) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	evidence, err := postAttest(ctx, attestURL, nonce)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	_, err = guestverify.VerifyEvidence(evidence, nonce, exp)
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
