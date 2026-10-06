package getkubeconfig

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// attestCredentialRelease requests a fresh report over the verified ARmTLS
// channel. Only an operator holding the measured launch key can ask the
// credential service to call the guest's loopback attester.
func attestCredentialRelease(ctx context.Context, client *http.Client, baseURL string, keyPEM []byte, exp platformVerifier) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("operator key: %w", err)
	}
	body, err := json.Marshal(credrelease.AttestRequest{Nonce: nonce})
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
	_, err = verifyEvidence(evidence, nonce, exp)
	return err
}
