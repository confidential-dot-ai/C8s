package cds

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// TestHACAEndpointFailsWhenNotServing: an HA replica that cannot issue must
// answer /ca with an error, never 200 and an empty bundle.
func TestHACAEndpointFailsWhenNotServing(t *testing.T) {
	limiter, err := issuer.NewIPRateLimiter(1, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	other, err := issuer.NewIPRateLimiter(1, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	var serving []byte
	h := newRouter(dependencies{
		MaxRequestSize: 1, RateLimiter: limiter, ChallengeLimiter: other,
		ReadyFn:      func() bool { return true },
		CACertSource: func() []byte { return serving },
	})
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ca", nil))
		return rec
	}
	if rec := get(); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("not serving: %d %q", rec.Code, rec.Body.String())
	}
	serving = []byte("-----BEGIN CERTIFICATE-----\n")
	if rec := get(); rec.Code != http.StatusOK {
		t.Fatalf("serving: %d", rec.Code)
	}
	_ = time.Second
}
