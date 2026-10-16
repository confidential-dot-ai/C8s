// Package allowlistclient is the HTTP client for the CDS allowlist API.
//
// Reads (List, Fetch) are unauthenticated; the attested armTLS channel to CDS
// provides their integrity. Writes bind an operator credential to the exact
// method, path, and body via Authorizer, so a captured token cannot be replayed
// against a different payload.
package allowlistclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// requestTimeout bounds one CDS call; the peer decides whether it ever answers.
const requestTimeout = 30 * time.Second

// Client is an HTTP client for the CDS allowlist API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new allowlist client.
func NewClient(baseURL string) Client {
	return Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: &http.Client{Timeout: requestTimeout}}
}

// NewClientWithHTTP creates a new allowlist client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient}
}

// Authorizer produces the HTTP Authorization header value for a mutation,
// binding it to the exact method, URL path, and body the client will send.
// Implemented by operatorauth.Signer.
type Authorizer = operatorauth.Authorizer

// List returns the current allowlist and its version (the ETag counter).
func (c Client) List(ctx context.Context) (*allowlist.Allowlist, string, error) {
	served, notModified, err := c.fetch(ctx, "", nil)
	if err != nil {
		return nil, "", err
	}
	if notModified {
		// Unreachable without an If-None-Match, but treat as an empty response.
		return nil, "", fmt.Errorf("unexpected 304 without If-None-Match")
	}
	return served.Allowlist, VersionFromETag(served.ETag), nil
}

// Fetch issues GET /allowlist with If-None-Match. notModified is true on a 304
// (allowlist nil, etag ""); on 200 the parsed allowlist and new ETag are
// returned. Used by enforcers polling for changes.
func (c Client) Fetch(ctx context.Context, ifNoneMatch string) (*allowlist.Allowlist, string, bool, error) {
	served, notModified, err := c.FetchServed(ctx, ifNoneMatch)
	return served.Allowlist, served.ETag, notModified, err
}

// Served is an allowlist as CDS served it.
type Served struct {
	Allowlist *allowlist.Allowlist
	ETag      string
	// Digest is "sha256:<hex>" of the exact bytes served. CDS serves
	// Allowlist.Canonical, so this is the policy digest it stamps into
	// workload certificates and nodes measure into RTMR[3].
	Digest string
}

// FetchServed is Fetch that also returns the digest of the served bytes.
func (c Client) FetchServed(ctx context.Context, ifNoneMatch string) (Served, bool, error) {
	return c.fetch(ctx, ifNoneMatch, nil)
}

// CanonicalBytes returns the validated bytes served by CDS without rewriting
// them. Workload certificates stamp their hash, so exports must preserve them.
func (c Client) CanonicalBytes(ctx context.Context) ([]byte, string, error) {
	var body []byte
	served, notModified, err := c.fetch(ctx, "", &body)
	if err != nil {
		return nil, "", err
	}
	if notModified {
		return nil, "", fmt.Errorf("unexpected 304 without If-None-Match")
	}
	return body, VersionFromETag(served.ETag), nil
}

func (c Client) fetch(ctx context.Context, ifNoneMatch string, raw *[]byte) (Served, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/allowlist", nil)
	if err != nil {
		return Served{}, false, fmt.Errorf("create request: %w", err)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Served{}, false, fmt.Errorf("fetch allowlist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		io.Copy(io.Discard, resp.Body)
		return Served{}, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := readCapped(resp.Body, maxAllowlistResponseBytes)
		return Served{}, false, &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if ct := resp.Header.Get("Content-Type"); !isJSONContentType(ct) {
		return Served{}, false, fmt.Errorf("fetch allowlist: unexpected content type: %s", ct)
	}

	body, err := readCapped(resp.Body, maxAllowlistResponseBytes)
	if err != nil {
		return Served{}, false, err
	}
	al, err := allowlist.ParseServedJSON(body)
	if err != nil {
		return Served{}, false, err
	}
	if raw != nil {
		*raw = body
	}
	sum := sha256.Sum256(body)
	return Served{Allowlist: al, ETag: resp.Header.Get("ETag"), Digest: "sha256:" + hex.EncodeToString(sum[:])}, false, nil
}

// ReplaceAll atomically replaces the entire allowlist. CDS assigns the new
// version.
func (c Client) ReplaceAll(ctx context.Context, al *allowlist.Allowlist, auth Authorizer) error {
	data, err := al.Canonical()
	if err != nil {
		return err
	}
	return c.mutate(ctx, http.MethodPut, "/allowlist", data, auth)
}

// PutWorkload creates or replaces one named workload entry.
func (c Client) PutWorkload(ctx context.Context, name string, w allowlist.Workload, auth Authorizer) error {
	data, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return c.mutate(ctx, http.MethodPut, "/allowlist/workloads/"+url.PathEscape(name), data, auth)
}

// DeleteWorkload removes one named workload entry. Returns a 404 StatusError if
// it is absent.
func (c Client) DeleteWorkload(ctx context.Context, name string, auth Authorizer) error {
	return c.mutate(ctx, http.MethodDelete, "/allowlist/workloads/"+url.PathEscape(name), nil, auth)
}

// mutate sends a body-bound, authorized write. auth is called with the exact
// method, path, and bytes sent, so the token's bindings match what CDS receives.
func (c Client) mutate(ctx context.Context, method, path string, body []byte, auth Authorizer) error {
	if auth == nil {
		return fmt.Errorf("allowlistclient: nil Authorizer")
	}
	req, err := operatorauth.NewRequest(ctx, method, c.baseURL+path, body, auth)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

// VersionFromETag extracts a non-empty N from a weak ETag of the form W/"N",
// or "" for anything else. A strong ETag yields "" by design: CDS only emits
// W/"N". Exported because enforcers polling the allowlist track the same
// counter for epoch anti-rollback.
func VersionFromETag(etag string) string {
	v, _ := weakVersion(etag)
	return v
}

// weakVersion returns N from a weak ETag W/"N" with a non-empty N.
func weakVersion(etag string) (string, bool) {
	v, ok := strings.CutPrefix(etag, `W/"`)
	if !ok {
		return "", false
	}
	v, ok = strings.CutSuffix(v, `"`)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// maxAllowlistResponseBytes caps CDS response bodies. Generous for a realistic
// fleet but bounded so a compromised or buggy CDS can't OOM the plugin process.
const maxAllowlistResponseBytes = 4 * 1024 * 1024

var errAllowlistResponseTooLarge = fmt.Errorf("allowlist response exceeds %d bytes", maxAllowlistResponseBytes)

func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	body, err := readutil.ReadAll(r, maxBytes)
	if errors.Is(err, readutil.ErrTooLarge) {
		return nil, errAllowlistResponseTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}

// StatusError represents a non-success HTTP response.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("server returned %d", e.Status)
}
