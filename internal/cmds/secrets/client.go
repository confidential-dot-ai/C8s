package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// client writes secrets to CDS over an attested channel.
type client struct {
	baseURL string
	http    *http.Client
}

// authorizer mints the operator Authorization header for one write, bound to
// its method, path, and body. Implemented by operatorauth.Signer.
type authorizer = operatorauth.Authorizer

// result is what a write did. Created reports a path that held nothing;
// Existing names what put the value the write displaced, or on a refusal what
// is still there.
type result struct {
	Created  bool
	Existing intsecrets.Origin
	// Refused reports that the path already held a value and the write did not
	// carry overwrite intent, so nothing changed.
	Refused bool
}

// put sends one value. overwrite travels in the body rather than the URL so the
// operator token's body binding covers it.
func (c client) put(ctx context.Context, path string, value []byte, overwrite bool, auth authorizer) (result, error) {
	body, err := json.Marshal(intsecrets.PutRequest{
		Value:     base64.StdEncoding.EncodeToString(value),
		Overwrite: overwrite,
	})
	if err != nil {
		return result{}, err
	}

	url := c.baseURL + "/secrets" + path
	req, err := operatorauth.NewRequest(ctx, http.MethodPut, url, body, auth)
	if err != nil {
		return result{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return result{}, fmt.Errorf("read response: %w", err)
	}

	// A refused write answers 409 with a JSON body; a spent token answers 409
	// with a plain-text error.
	refused := resp.StatusCode == http.StatusConflict && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json")
	switch {
	case resp.StatusCode == http.StatusCreated,
		refused,
		resp.StatusCode == http.StatusOK && overwrite:
		var pr intsecrets.PutResponse
		if err := json.Unmarshal(raw, &pr); err != nil {
			return result{}, fmt.Errorf("decode response: %w", err)
		}
		return result{
			Created:  pr.Created,
			Existing: pr.Existing,
			Refused:  refused,
		}, nil
	case resp.StatusCode == http.StatusOK:
		// 200 answers a replacement. Reading it as anything else would let the
		// CLI report a refusal for a write that landed.
		return result{}, fmt.Errorf("cds replaced a value for a request that did not ask to: %s", path)
	default:
		return result{}, fmt.Errorf("cds returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
}

// explain asks CDS what a sandbox resolves to and why.
func (c client) explain(ctx context.Context, sandboxID string, auth authorizer) (intsecrets.ExplainResponse, error) {
	var out intsecrets.ExplainResponse
	url := c.baseURL + "/secrets-explain/" + sandboxID
	req, err := operatorauth.NewRequest(ctx, http.MethodGet, url, nil, auth)
	if err != nil {
		return out, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return out, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("cds returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// maxResponseBytes bounds a CDS reply. The largest is an explain report over
// every workload entry; anything approaching this is a wrong endpoint.
const maxResponseBytes = 1 << 20
