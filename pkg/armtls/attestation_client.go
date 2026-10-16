package armtls

import (
	"net/http"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
)

// attestationRequestTimeout matches remote.NewClient's per-call bound.
const attestationRequestTimeout = 60 * time.Second

// NewAttestationClient is remote.NewClient over [NewDirectHTTPClient].
func NewAttestationClient(baseURL string) remote.Client {
	return remote.NewClientWithHTTP(baseURL, NewDirectHTTPClient(attestationRequestTimeout))
}

// NewDirectHTTPClient returns an HTTP client for the attestation-api that
// ignores HTTP_PROXY and friends: a proxy variable in a component's
// environment, which its allowlist entry leaves open, would otherwise choose
// who answers /attest and /verify. Every client shares one transport, so
// repeated calls reuse its connection pool.
func NewDirectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: directTransport()}
}

var directTransport = sync.OnceValue(func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return t
})
