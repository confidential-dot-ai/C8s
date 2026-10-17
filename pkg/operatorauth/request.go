package operatorauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Authorizer binds an Authorization header to an HTTP method, URL path, and
// body. Signer implements it with a short-lived operator token.
type Authorizer interface {
	Authorization(method, path string, body []byte) (string, error)
}

// NewRequest constructs a request and authorizes its actual method, parsed URL
// path, and body. It owns a copy of body so later changes to the input cannot
// invalidate the token. Callers must not change the returned method, path, or
// body; content type, transport, and response handling remain their concern.
func NewRequest(ctx context.Context, method, url string, body []byte, auth Authorizer) (*http.Request, error) {
	if auth == nil {
		return nil, fmt.Errorf("operatorauth: nil Authorizer")
	}
	body = bytes.Clone(body)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	authz, err := auth.Authorization(req.Method, req.URL.Path, body)
	if err != nil {
		return nil, fmt.Errorf("authorize request: %w", err)
	}
	req.Header.Set("Authorization", authz)
	return req, nil
}

// StatusError is a CDS response whose status the call did not expect.
type StatusError struct {
	Status int    // HTTP status code
	Body   string // first 4 KiB of the response body, trimmed
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("server returned %d", e.Status)
}

// ResponseError reads the start of resp's body into a StatusError.
func ResponseError(resp *http.Response) *StatusError {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
}
