package cds

import (
	"bytes"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

type r4RouteMesh struct{ ca issuer.CurrentCA }

func (m *r4RouteMesh) Current() issuer.CurrentCA { return m.ca }

func TestRoutePutFollowsCurrentMeshCA(t *testing.T) {
	store := inMemoryStore(t)
	f := newRouteFixture(t, store)
	oldCA, newCA := testMeshCA(t).Current(), testMeshCA(t).Current()
	source := &r4RouteMesh{ca: oldCA}
	authorize := operatorauth.Verifier{Keys: []*ecdsa.PublicKey{f.key}}.Authorize
	router := newRouter(dependencies{
		Routes:           routeHandler{Store: store, Authorize: authorize, MeshCA: source},
		MeshCA:           source,
		ReadyFn:          func() bool { return true },
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	})
	put := func(body []byte, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, routes.Path, bytes.NewReader(body))
		req.Header.Set("Authorization", sign(t, f.signer, http.MethodPut, routes.Path, body))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("PUT status=%d want=%d: %s", rec.Code, want, rec.Body)
		}
	}
	oldPEM := string(certutil.EncodeCertPEM(oldCA.CA.Cert.Raw))
	newPEM := string(certutil.EncodeCertPEM(newCA.CA.Cert.Raw))
	put(manifest(t, 1, oldPEM), http.StatusUnprocessableEntity)
	seed := manifest(t, 1, f.otherPEM)
	put(seed, http.StatusNoContent)
	source.ca = newCA // same router/handler stays alive, as across RotateKey
	put(manifest(t, 2, newPEM), http.StatusUnprocessableEntity)
	got, err := store.LoadRoutes()
	if err != nil || !bytes.Equal(got.Manifest, seed) {
		t.Fatalf("refused write changed store: %v", err)
	}
	// CDS trusts only the current generation. A genuinely retired CA is no
	// longer excluded here, matching a CDS restarted after RotateKey. Routing
	// consumers still exclude all generations in their own trusted bundle.
	retired := manifest(t, 2, oldPEM)
	put(retired, http.StatusNoContent)
	source.ca = issuer.CurrentCA{}
	put(manifest(t, 3, f.otherPEM), http.StatusInternalServerError)
	got, err = store.LoadRoutes()
	if err != nil || !bytes.Equal(got.Manifest, retired) {
		t.Fatalf("keyless write changed store: %v", err)
	}
}
