package types

import (
	"encoding/json"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// ChallengeResponse is the response body for POST /authenticate.
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
}

// NonceRequest is the request body of a nonce-bound evidence endpoint
// (cred-release /attest, pod-status /v1/evidence): a fresh 32-byte nonce,
// base64 in JSON.
type NonceRequest struct {
	Nonce []byte `json:"nonce"`
}

// AttestRequestBody is the request body for POST /attest.
type AttestRequestBody struct {
	Challenge string                       `json:"challenge"`
	Evidence  teetypes.AttestationEvidence `json:"evidence"`
	CSR       string                       `json:"csr"`

	// SandboxToken is the inventory-signed sandbox identity of the requesting
	// pod (workloadclaims.SignedSandboxToken as JSON): its CRI sandbox ID and
	// the inventory's callback address, bound to the requester's CSR key and
	// this request's challenge, signed by the inventory's armTLS key.
	// CDS verifies the token, asks that inventory which images
	// the sandbox is running, and stamps the sandbox ID into the leaf
	// (armtls.OIDSandboxID) — docs/armtls.md, "Sandbox identity". Kept opaque
	// here (types must not import workloadclaims).
	SandboxToken json.RawMessage `json:"sandbox_token,omitempty"`

	// PodClaims is a complete guest-owned admission snapshot bound directly
	// into fresh quote REPORTDATA. Mutually exclusive with SandboxToken and
	// the node profile's RuntimeExtensions; it carries its own complete log.
	PodClaims json.RawMessage `json:"pod_claims,omitempty"`

	// RuntimeExtensions is the requester's claimed TDX RTMR[3] runtime
	// extension list, canonical digests in extend order. CDS replays it
	// against the quote and trusts only the prefix that matches.
	RuntimeExtensions []string `json:"runtime_extensions,omitempty"`
}
