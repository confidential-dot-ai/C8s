package armtls

import (
	"net/http"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
)

// attestationRequestTimeout matches remote.NewClient's per-call bound.
const attestationRequestTimeout = 60 * time.Second

// NewAttestationClient is remote.NewClient over a transport that ignores
// HTTP_PROXY and friends. remote.NewClient uses http.DefaultTransport, so a
// proxy variable in a component's environment, which its allowlist entry
// leaves open, would choose who answers /verify.
func NewAttestationClient(baseURL string) remote.Client {
	return remote.NewClientWithHTTP(baseURL, &http.Client{Timeout: attestationRequestTimeout, Transport: directTransport()})
}

func directTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return t
}
