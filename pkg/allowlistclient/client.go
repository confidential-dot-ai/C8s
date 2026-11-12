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
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Client is an HTTP client for the CDS allowlist API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	// query is appended to GET /allowlist.
	query string
}

// NewClientWithHTTP creates a new allowlist client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient}
}

// ForNodes returns c reading the allowlist in effect on nodes
// (allowlist.NodeQuery).
func (c Client) ForNodes() Client {
	c.query = "?" + allowlist.NodeQuery
	return c
}

// Authorizer produces the HTTP Authorization header value for a mutation,
// binding it to the exact method, URL path, and body the client will send.
// Implemented by operatorauth.Signer.
type Authorizer = operatorauth.Authorizer

// List returns the current allowlist and its version.
func (c Client) List(ctx context.Context) (*allowlist.Allowlist, string, error) {
	served, notModified, err := c.fetch(ctx, "", nil)
	if err != nil {
		return nil, "", err
	}
	if notModified {
		// Unreachable without an If-None-Match, but treat as an empty response.
		return nil, "", fmt.Errorf("unexpected 304 without If-None-Match")
	}
	return served.Allowlist, served.Version, nil
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
	// Version is the store version CDS served the document at, the one
	// nodes refuse to go below; "" when the response named none.
	Version string
	// Digest is "sha256:<hex>" of the exact bytes served. CDS serves
	// Allowlist.Canonical, so this is the policy digest it stamps into
	// workload certificates and nodes measure into RTMR[3].
	Digest string
}

// FetchServed is Fetch that also returns the digest of the served bytes and
// the version. On a 304 only the version is set: the one CDS now serves the
// document the request named at.
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
	return body, served.Version, nil
}

func (c Client) fetch(ctx context.Context, ifNoneMatch string, raw *[]byte) (Served, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/allowlist"+c.query, nil)
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
		return Served{Version: servedVersion(resp.Header)}, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Served{}, false, operatorauth.ResponseError(resp)
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
	return Served{
		Allowlist: al,
		ETag:      resp.Header.Get("ETag"),
		Version:   servedVersion(resp.Header),
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
	}, false, nil
}

// Object returns the allowlist document of the CDS's history whose digest is
// digest (GET /allowlist/objects/sha256/<hex>). It refuses bytes that hash to
// anything else, so the caller needs no trust in the store for them.
func (c Client) Object(ctx context.Context, digest [sha256.Size]byte) (*allowlist.Allowlist, error) {
	path := "/allowlist/objects/sha256/" + hex.EncodeToString(digest[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, operatorauth.ResponseError(resp)
	}
	body, err := readCapped(resp.Body, maxAllowlistResponseBytes)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(body) != digest {
		return nil, fmt.Errorf("fetch %s: the body hashes to another digest", path)
	}
	return allowlist.ParseServedJSON(body)
}

// ReplaceAll atomically replaces the entire allowlist. CDS assigns the new
// version. A non-empty version makes the write conditional: CDS refuses it
// with a 412 *operatorauth.StatusError unless the allowlist is still at that
// version (the Version of the read it was built from), so the write never
// overwrites a write made since.
func (c Client) ReplaceAll(ctx context.Context, al *allowlist.Allowlist, version string, auth Authorizer) error {
	data, err := al.Canonical()
	if err != nil {
		return err
	}
	ifMatch := ""
	if version != "" {
		// The version names exactly one stored document, so it is a strong
		// validator, as If-Match's strong comparison requires.
		ifMatch = `"` + version + `"`
	}
	return c.mutate(ctx, http.MethodPut, "/allowlist", data, ifMatch, auth)
}

// A write answered 429 (rate limited) or 503 (nothing is serving the API) is
// sent again, up to maxWriteAttempts times in all. It waits the response's
// Retry-After, capped at maxRetryWait, or without one firstRetryWait doubling
// per attempt.
const (
	maxWriteAttempts = 6
	maxRetryWait     = 30 * time.Second
	firstRetryWait   = 500 * time.Millisecond
)

// mutate sends a body-bound, authorized write, sending it again while the
// refusal only says "not now". Each attempt carries a token of its own: CDS
// spends a token once. Any other refusal is final.
func (c Client) mutate(ctx context.Context, method, path string, body []byte, ifMatch string, auth Authorizer) error {
	if auth == nil {
		return fmt.Errorf("allowlistclient: nil Authorizer")
	}
	for attempt := 1; ; attempt++ {
		retryAfter, err := c.send(ctx, method, path, body, ifMatch, auth)
		if err == nil {
			return nil
		}
		if !saysNotNow(err) {
			return err
		}
		if attempt == maxWriteAttempts {
			return fmt.Errorf("%w (gave up after %d attempts)", err, attempt)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w; stopped waiting to retry: %w", err, ctx.Err())
		case <-time.After(retryWait(retryAfter, attempt)):
		}
	}
}

// saysNotNow reports whether a refusal only means "not now": the write was
// rate limited, or nothing was serving the API.
func saysNotNow(err error) bool {
	var refusal *operatorauth.StatusError
	if !errors.As(err, &refusal) {
		return false
	}
	return refusal.Status == http.StatusTooManyRequests || refusal.Status == http.StatusServiceUnavailable
}

// send makes one attempt of a write. auth is called with the exact method,
// path, and bytes sent, so the token's bindings match what CDS receives. A
// refusal comes back as a *operatorauth.StatusError with the answer's
// Retry-After.
func (c Client) send(ctx context.Context, method, path string, body []byte, ifMatch string, auth Authorizer) (string, error) {
	req, err := operatorauth.NewRequest(ctx, method, c.baseURL+path, body, auth)
	if err != nil {
		return "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.Header.Get("Retry-After"), operatorauth.ResponseError(resp)
	}
	io.Copy(io.Discard, resp.Body)
	return "", nil
}

// retryWait is how long to wait before attempt+1: the Retry-After seconds
// when the server sent them, else firstRetryWait doubled per attempt made.
func retryWait(retryAfter string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds >= 0 {
		return min(time.Duration(seconds)*time.Second, maxRetryWait)
	}
	return min(firstRetryWait<<(attempt-1), maxRetryWait)
}

// servedVersion is the version a GET /allowlist response names in its
// VersionHeader, or in the ETag of a CDS released before that header.
func servedVersion(h http.Header) string {
	if version := h.Get(allowlist.VersionHeader); version != "" {
		return version
	}
	return versionOfEarlierCDS(h.Get("ETag"))
}

// versionOfEarlierCDS is the version a CDS released before VersionHeader
// names as the N of its ETag W/"N", or "" for any other ETag.
func versionOfEarlierCDS(etag string) string {
	v, ok := strings.CutPrefix(etag, `W/"`)
	if !ok {
		return ""
	}
	v, ok = strings.CutSuffix(v, `"`)
	if !ok {
		return ""
	}
	return v
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
