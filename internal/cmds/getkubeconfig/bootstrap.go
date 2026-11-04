package getkubeconfig

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// attestCredentialRelease requests a fresh report over the verified armTLS
// channel. Only an operator holding the measured launch key can ask the
// credential service to call the guest's loopback attester. The response's
// runtime extensions, read after the quote and authenticated by the channel,
// replace the leaf's list, which may predate the node's latest policy.
func attestCredentialRelease(ctx context.Context, client *http.Client, baseURL string, keyPEM []byte, exp guestverify.Policy) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("operator key: %w", err)
	}
	body, err := json.Marshal(types.NonceRequest{Nonce: nonce})
	if err != nil {
		return err
	}
	req, err := operatorauth.NewRequest(ctx, http.MethodPost, baseURL+credrelease.AttestPath, body, signer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	evidence, err := readAttestationResponse(client, req)
	if err != nil {
		return fmt.Errorf("credential-service attestation: %w", err)
	}
	var response credrelease.AttestResponse
	if json.Unmarshal(evidence, &response) == nil && exp.MeasuresPolicies() && response.RuntimeExtensions != nil {
		exp = exp.WithMeasuredPolicies(response.RuntimeExtensions)
	}
	_, err = guestverify.VerifyEvidence(evidence, nonce, exp)
	return err
}
