package types

import (
	"encoding/json"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ChallengeResponse is the response body for POST /authenticate.
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
}

// AttestRequestBody is the request body for POST /attest.
type AttestRequestBody struct {
	Challenge string                       `json:"challenge"`
	Evidence  teetypes.AttestationEvidence `json:"evidence"`
	CSR       string                       `json:"csr"`

	// SandboxToken is the inventory-signed sandbox identity of the requesting
	// pod (workloadclaims.SignedSandboxToken as JSON): its CRI sandbox ID and
	// the inventory's callback address, bound to the requester's CSR key and
	// this request's challenge, signed by the inventory's ARmTLS key.
	// CDS verifies the token, asks that inventory which images
	// the sandbox is running, and stamps the sandbox ID into the leaf
	// (armtls.OIDSandboxID) — docs/armtls.md, "Sandbox identity". Kept opaque
	// here (types must not import workloadclaims).
	SandboxToken json.RawMessage `json:"sandbox_token,omitempty"`
}
