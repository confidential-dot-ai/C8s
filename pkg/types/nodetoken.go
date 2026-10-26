package types

import (
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// NodeTokenRequestBody is the request body for POST /node-token: a node's
// fresh evidence, bound to its node key and a challenge from /authenticate,
// asking for a join token for one API server.
type NodeTokenRequestBody struct {
	Challenge string                       `json:"challenge"`
	Evidence  teetypes.AttestationEvidence `json:"evidence"`

	// NodeKey is the node's ECDSA P-256 public key, PKIX DER in base64, the
	// key the evidence's report data binds with the challenge. The token's
	// subject, the node's name, is derived from it.
	NodeKey string `json:"node_key"`

	// Audience is the hostname of the API server the token is for.
	Audience string `json:"audience"`

	// RuntimeExtensions is the node's claimed TDX RTMR[3] runtime extension
	// list, as in AttestRequestBody.
	RuntimeExtensions []string `json:"runtime_extensions,omitempty"`
}

// NodeTokenResponse is the response body for POST /node-token.
type NodeTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
