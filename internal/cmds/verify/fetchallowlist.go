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

// fetchPolicy GETs url from any peer: callers authenticate what it returns.
func fetchPolicy(ctx context.Context, url, serverName string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := insecureClient(serverName, timeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes+1))
		if err == nil && len(body) > maxPolicyBytes {
			err = fmt.Errorf("response exceeds %d bytes", maxPolicyBytes)
		}
		return body, err
	case http.StatusNotFound:
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
}
