package armtls

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewVerifyingHTTPClient returns an http.Client whose TLS handshake
// verifies the peer's armTLS attestation extension against the supplied
// pins (launch-measurement reference values plus any TDX RTMR pins). Zero pins
// falls back to TOFU on the attestation extension — UNSAFE outside
// development; the caller is expected to warn.
//
// attestationApiURL is the local attestation-api whose /verify endpoint
// performs all peer evidence verification. Required: every handshake
// verification is delegated to it; there is no in-process fallback.
//
// Connection-pool and timeout knobs: 5s dial, 10s response-header, 30s
// overall, MaxIdleConns=5, MaxConnsPerHost=2.
func NewVerifyingHTTPClient(pins Pins, attestationApiURL string) (*http.Client, error) {
	if attestationApiURL == "" {
		return nil, fmt.Errorf("armtls client config: attestation-api URL is required")
	}
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{
		Policy: pins.VerifyPolicy(attestationApiURL),
	})
	if err != nil {
		return nil, fmt.Errorf("armtls client config: %w", err)
	}
	return HTTPClient(tlsCfg), nil
}

// HTTPClient wraps tlsCfg in the standard armTLS client shape: 5s dial, 10s
// response-header, 30s overall, MaxIdleConns=5, MaxConnsPerHost=2. Shared by
// the delegated verifier above and the in-process one (internal/localverify)
// so the two clients cannot drift on pooling or timeouts.
func HTTPClient(tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          5,
			MaxConnsPerHost:       2,
			TLSClientConfig:       tlsCfg,
		},
	}
}
