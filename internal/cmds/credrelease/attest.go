package credrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// AttestPath serves operator-authorized, nonce-bound bootstrap evidence.
const AttestPath = "/attest"

const attestTimeout = 30 * time.Second

// AttestResponse is the evidence envelope plus the RTMR[3] runtime extensions
// this node journaled, read after the quote so the list may run ahead of it
// but never lag it. The verified armTLS channel authenticates the list.
type AttestResponse struct {
	teetypes.AttestationEvidence
	RuntimeExtensions []string `json:"runtime_extensions,omitempty"`
}

// localEvidenceGenerator fixes the upstream to the configured local API.
type localEvidenceGenerator struct {
	client attestclient.Client
	apiURL string
}

func (g localEvidenceGenerator) GenerateEvidence(ctx context.Context, nonce []byte) (teetypes.AttestationEvidence, error) {
	response, err := g.client.GenerateEvidenceContext(ctx, g.apiURL, nonce)
	return response.Envelope(), err
}

// serveAttest is reached only after ServeHTTP authorizes the request: the
// operator token covers these exact types.NonceRequest bytes.
func (h *Handler) serveAttest(w http.ResponseWriter, r *http.Request, body []byte) {
	var req types.NonceRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid attestation request", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF || len(req.Nonce) != 32 {
		http.Error(w, "invalid attestation request", http.StatusBadRequest)
		return
	}
	if h.attester == nil {
		http.Error(w, "attestation unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), attestTimeout)
	defer cancel()
	evidence, err := h.attester.GenerateEvidence(ctx, req.Nonce)
	if err != nil {
		http.Error(w, "attestation unavailable", http.StatusBadGateway)
		return
	}
	response, err := json.Marshal(AttestResponse{AttestationEvidence: evidence, RuntimeExtensions: h.measuredPolicies.Policies()})
	if err != nil {
		http.Error(w, "attestation unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(response)
}
