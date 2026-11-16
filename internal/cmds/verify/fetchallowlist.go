package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxPolicyBytes bounds one fetched policy object or signature.
const maxPolicyBytes = 16 << 20

// errNotFound is a 404 from fetchPolicy: CDS holds no such object or signature.
var errNotFound = errors.New("not found")

// policyClient returns the client for fetchPolicy, which takes a redirect as
// its status. The caller closes its idle connections when done.
func policyClient(serverName string, timeout time.Duration) *http.Client {
	client := insecureClient(serverName, timeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// fetchPolicy GETs url with a policyClient from any peer: callers
// authenticate what it returns. A transport failure or timeout is a
// *connectError.
func fetchPolicy(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &connectError{err}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes+1))
		if err != nil {
			return nil, &connectError{err}
		}
		if len(body) > maxPolicyBytes {
			return nil, fmt.Errorf("response exceeds %d bytes", maxPolicyBytes)
		}
		return body, nil
	case http.StatusNotFound:
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
}
