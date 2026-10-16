// Package routesclient is the HTTP client for the CDS route API: GET and PUT
// /routes (route policy §8).
//
// Get returns the envelope as served and verifies nothing; a caller that
// trusts operator keys runs routes.VerifySigned on it (W2). Put signs the
// exact manifest bytes it sends, so the token's htu is exactly /routes.
package routesclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// maxEnvelopeBytes bounds a GET /routes response: base64 of the CDS's 1 MiB
// write cap plus the token, with room to spare.
const maxEnvelopeBytes = 4 << 20

// ErrNotFound reports that the CDS stores no route manifest.
var ErrNotFound = errors.New("no route manifest stored on CDS")

// Client talks to one CDS. The zero value is unusable; construct with New.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New returns a client for the CDS at baseURL, sending through httpClient,
// which carries the attestation check and timeout. baseURL must have no path,
// query or fragment: W2 requires a write token's htu to be exactly /routes.
func New(baseURL string, httpClient *http.Client) (Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Client{}, fmt.Errorf("invalid CDS URL %q: want http(s)://host[:port]", baseURL)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Client{}, fmt.Errorf("CDS URL %q must have no path, query or fragment: a route write token is bound to %s exactly", baseURL, routes.Path)
	}
	if httpClient == nil {
		return Client{}, errors.New("routesclient: nil HTTP client")
	}
	return Client{baseURL: u.Scheme + "://" + u.Host, httpClient: httpClient}, nil
}

// Get fetches the stored signed manifest. It returns ErrNotFound on 404.
func (c Client) Get(ctx context.Context) (routes.Envelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+routes.Path, nil)
	if err != nil {
		return routes.Envelope{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return routes.Envelope{}, fmt.Errorf("fetch route manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return routes.Envelope{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return routes.Envelope{}, operatorauth.ResponseError(resp)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return routes.Envelope{}, fmt.Errorf("fetch route manifest: unexpected content type %q", resp.Header.Get("Content-Type"))
	}
	body, err := readutil.ReadAll(resp.Body, maxEnvelopeBytes)
	if err != nil {
		return routes.Envelope{}, fmt.Errorf("read route manifest: %w", err)
	}
	var env routes.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return routes.Envelope{}, err
	}
	return env, nil
}

// Put sends manifest verbatim, authorized by auth for PUT /routes. A non-empty
// ifMatch is the lower-case hex route digest of the manifest the caller read;
// CDS then refuses the write with 412 if another one landed since. An
// *operatorauth.StatusError carries the CDS's refusal: 400, 401, 409, 412 or
// 422 (C3).
func (c Client) Put(ctx context.Context, manifest []byte, auth operatorauth.Authorizer, ifMatch string) error {
	req, err := operatorauth.NewRequest(ctx, http.MethodPut, c.baseURL+routes.Path, manifest, auth)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("write route manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return operatorauth.ResponseError(resp)
	}
	return nil
}
