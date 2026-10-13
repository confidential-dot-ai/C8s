package verify

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxPolicyBytes bounds one fetched policy object or signature.
const maxPolicyBytes = 16 << 20

// fetchPolicy GETs url. With certSHA256 set the connection must present that
// serving leaf (fetchAttested); otherwise any peer is accepted.
func fetchPolicy(ctx context.Context, url, serverName, certSHA256 string, timeout time.Duration) ([]byte, error) {
	var resp *http.Response
	var err error
	if certSHA256 != "" {
		resp, err = fetchAttested(ctx, url, serverName, certSHA256, timeout)
	} else {
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err != nil {
			return nil, err
		}
		resp, err = insecureClient(serverName, timeout).Do(req)
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
}

// attestedServingLeaf is the hex SHA-256 of the serving leaf a live attest-lb
// gather bound its evidence to, "" for any other gather.
func attestedServingLeaf(ev *evidence) string {
	if !ev.fresh || ev.servingLeafSHA256 == "" {
		return ""
	}
	sum, err := base64.RawURLEncoding.DecodeString(ev.servingLeafSHA256)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(sum)
}
