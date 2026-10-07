package cdsclient

import (
	"net/http"
	"time"
)

// plainHTTPClient returns an *http.Client without armTLS. It is only safe for
// tests that talk to plain httptest.NewServer fakes. Production code MUST
// leave Config.HTTPClient nil so NewClient builds an armTLS-verifying
// transport.
func plainHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
