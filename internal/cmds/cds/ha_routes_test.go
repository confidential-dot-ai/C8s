package cds

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// switchableCA is a mesh CA that reads empty until set, as an HA replica's
// does before it may issue.
type switchableCA struct{ current issuer.CurrentCA }

func (s *switchableCA) Current() issuer.CurrentCA { return s.current }

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
	ca := &switchableCA{}
	h := newRouter(dependencies{
		MaxRequestSize: 1, RateLimiter: limiter, ChallengeLimiter: other,
		ReadyFn: func() bool { return true },
		MeshCA:  ca,
	})
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ca", nil))
		return rec
	}
	if rec := get(); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("not serving: %d %q", rec.Code, rec.Body.String())
	}
	mesh, err := issuer.NewMeshCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca.current = mesh.Current()
	if rec := get(); rec.Code != http.StatusOK || rec.Body.String() != string(ca.current.CertPEM) {
		t.Fatalf("serving: %d", rec.Code)
	}
}
