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
	"fmt"
	"io"
	"net/http"
)

// readAttestationResponse reads the evidence envelope, bounded.
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
