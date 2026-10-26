package attestclient

import (
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// NodeTokenPath is CDS's node token endpoint (docs/node-tokens.md).
const NodeTokenPath = "/node-token"

// ObtainNodeToken asks CDS for a join token for the hosted cluster API server
// named by audience. The node's evidence binds SHA-384(nodeKey || challenge),
// so the token's subject, derived from nodeKey, names only this node. As for
// certificates, the client must be built over an armTLS-verified transport.
func (c Client) ObtainNodeToken(ctx context.Context, attestationApiURL string, nodeKey crypto.PublicKey, audience string) (types.NodeTokenResponse, error) {
	ctx = contextOrBackground(ctx)
	der, err := x509.MarshalPKIXPublicKey(nodeKey)
	if err != nil {
		return types.NodeTokenResponse{}, fmt.Errorf("node key: %w", err)
	}
	challengeResp, err := c.AuthenticateContext(ctx)
	if err != nil {
		return types.NodeTokenResponse{}, fmt.Errorf("authenticate: %w", err)
	}
	challenge, err := base64.StdEncoding.DecodeString(challengeResp.Challenge)
	if err != nil {
		return types.NodeTokenResponse{}, fmt.Errorf("invalid base64 in challenge: %w", err)
	}
	reportData, err := armtls.ReportDataForKey(nodeKey, challenge)
	if err != nil {
		return types.NodeTokenResponse{}, err
	}
	asResp, err := c.GenerateEvidenceContext(ctx, attestationApiURL, reportData[:sha512.Size384])
	if err != nil {
		return types.NodeTokenResponse{}, fmt.Errorf("attestation-api: %w", err)
	}
	var extensions []string
	if asResp.Platform.IsTDX() {
		extensions = c.MeasuredPolicies.Policies()
	}
	body, err := json.Marshal(types.NodeTokenRequestBody{
		Challenge:         challengeResp.Challenge,
		Evidence:          asResp.Envelope(),
		NodeKey:           base64.StdEncoding.EncodeToString(der),
		Audience:          audience,
		RuntimeExtensions: extensions,
	})
	if err != nil {
		return types.NodeTokenResponse{}, err
	}
	respBody, err := c.do(ctx, http.MethodPost, NodeTokenPath, body)
	if err != nil {
		return types.NodeTokenResponse{}, err
	}
	var resp types.NodeTokenResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return types.NodeTokenResponse{}, fmt.Errorf("node token response: %w", err)
	}
	if resp.Token == "" || resp.ExpiresAt.IsZero() {
		return types.NodeTokenResponse{}, fmt.Errorf("node token response carries no token or expiry")
	}
	return resp, nil
}
