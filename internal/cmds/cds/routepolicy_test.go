package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

type routeFixture struct {
	router   http.Handler
	store    *allowlist.Store
	signer   *operatorauth.Signer
	rogue    *operatorauth.Signer
	key      *ecdsa.PublicKey
	meshCA   *x509.Certificate
	meshPEM  string
	otherPEM string
}

func operatorSigner(t *testing.T) (*operatorauth.Signer, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return signer, &key.PublicKey
}

// newRouteFixture mounts the route handler on the production router with the
// production operator verifier, over store.
func newRouteFixture(t *testing.T, store *allowlist.Store) *routeFixture {
	t.Helper()
	mesh, err := issuer.NewCA("mesh ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, err := issuer.NewCA("backend ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, key := operatorSigner(t)
	rogue, _ := operatorSigner(t)
	authorize := operatorauth.Verifier{Keys: []*ecdsa.PublicKey{key}, ClockSkew: 30 * time.Second}.Authorize
	return &routeFixture{
		router: newRouter(dependencies{
			Routes:           routeHandler{Store: store, Authorize: authorize, MeshCA: mesh.Cert},
			ReadyFn:          func() bool { return true },
			RateLimiter:      newTestRateLimiter(t),
			ChallengeLimiter: newTestRateLimiter(t),
			MaxRequestSize:   65536,
		}),
		store:    store,
		signer:   signer,
		rogue:    rogue,
		key:      key,
		meshCA:   mesh.Cert,
		meshPEM:  string(certutil.EncodeCertPEM(mesh.Cert.Raw)),
		otherPEM: string(certutil.EncodeCertPEM(other.Cert.Raw)),
	}
}

func inMemoryStore(t *testing.T) *allowlist.Store {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &store
}

// manifest returns manifest bytes at revision with one workload route, plus
// an address backend anchored on ca when ca is set.
func manifest(t *testing.T, revision int, ca string) []byte {
	t.Helper()
	rs := []any{map[string]any{"path": "/", "match": "prefix",
		"backend": map[string]any{"address": "vllm.ai.svc.cluster.local:8443", "workload": "vllm"}}}
	if ca != "" {
		rs = append(rs, map[string]any{"path": "/admin", "match": "prefix",
			"backend": map[string]any{"address": "admin.ops.svc.cluster.local:8443", "serverName": "admin.ops.svc", "ca": ca}})
	}
	b, err := json.Marshal(map[string]any{
		"schema":        routes.Schema,
		"revision":      revision,
		"notBefore":     "2026-09-01T00:00:00Z",
		"maxAgeSeconds": 86400,
		"hosts":         map[string]any{"app.example": map[string]any{"routes": rs}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *routeFixture) put(t *testing.T, body []byte, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	return f.putIfMatch(t, body, authorization, "")
}

func (f *routeFixture) putIfMatch(t *testing.T, body []byte, authorization, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, routes.Path, bytes.NewReader(body))
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *routeFixture) get(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, routes.Path, nil))
	return w
}

func sign(t *testing.T, s *operatorauth.Signer, method, path string, body []byte) string {
	t.Helper()
	h, err := s.Authorization(method, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestRoutePutStatus walks the C3 order against a store holding revision 5:
// each row fails at exactly one step, and the earlier step wins when two
// would fail.
func TestRoutePutStatus(t *testing.T) {
	type input struct {
		body []byte
		auth string
	}
	cases := []struct {
		name  string
		build func(t *testing.T, f *routeFixture) input
		want  int
	}{
		{"C3 unsigned 401", func(t *testing.T, f *routeFixture) input {
			return input{manifest(t, 6, ""), ""}
		}, http.StatusUnauthorized},
		{"W1 wrong key 401", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 6, "")
			return input{b, sign(t, f.rogue, http.MethodPut, routes.Path, b)}
		}, http.StatusUnauthorized},
		{"W1 token bound to another path 401", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 6, "")
			return input{b, sign(t, f.signer, http.MethodPut, "/allowlist", b)}
		}, http.StatusUnauthorized},
		{"W1 token bound to another body 401", func(t *testing.T, f *routeFixture) input {
			return input{manifest(t, 6, ""), sign(t, f.signer, http.MethodPut, routes.Path, manifest(t, 7, ""))}
		}, http.StatusUnauthorized},
		{"C3 wrong key before bad manifest 401", func(t *testing.T, f *routeFixture) input {
			b := []byte(`{"schema":"nope"}`)
			return input{b, sign(t, f.rogue, http.MethodPut, routes.Path, b)}
		}, http.StatusUnauthorized},
		{"C3 bad manifest 422", func(t *testing.T, f *routeFixture) input {
			b := []byte(`{"schema":"nope"}`)
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusUnprocessableEntity},
		{"C3 bad manifest before stale revision 422", func(t *testing.T, f *routeFixture) input {
			b := bytes.Replace(manifest(t, 5, ""), []byte(`"prefix"`), []byte(`"glob"`), 1)
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusUnprocessableEntity},
		{"C3 mesh CA anchor 422", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 6, f.meshPEM)
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusUnprocessableEntity},
		{"C3 mesh CA anchor before stale revision 422", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 5, f.meshPEM)
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusUnprocessableEntity},
		{"C3 equal revision 409", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 5, "")
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusConflict},
		{"C3 lower revision 409", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 4, "")
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusConflict},
		{"C2 next revision 204", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 6, "")
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusNoContent},
		{"C2 other CA anchor 204", func(t *testing.T, f *routeFixture) input {
			b := manifest(t, 9, f.otherPEM)
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusNoContent},
		{"C3 oversize body 400", func(t *testing.T, f *routeFixture) input {
			b := make([]byte, allowlistWriteBodyCap+1)
			return input{b, sign(t, f.signer, http.MethodPut, routes.Path, b)}
		}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteFixture(t, inMemoryStore(t))
			seed := manifest(t, 5, "")
			if err := f.store.ReplaceRoutes(routes.Envelope{Manifest: seed, Token: "seed"}, 5, ""); err != nil {
				t.Fatal(err)
			}
			in := tc.build(t, f)
			w := f.put(t, in.body, in.auth)
			if w.Code != tc.want {
				t.Fatalf("PUT /routes = %d, want %d; body=%s", w.Code, tc.want, w.Body)
			}
			got, err := f.store.LoadRoutes()
			if err != nil {
				t.Fatal(err)
			}
			want := routes.Envelope{Manifest: seed, Token: "seed"}
			if tc.want == http.StatusNoContent {
				want = routes.Envelope{Manifest: in.body, Token: strings.TrimPrefix(in.auth, "Bearer ")}
			}
			if !bytes.Equal(got.Manifest, want.Manifest) || got.Token != want.Token {
				t.Fatalf("stored manifest after %d is not the expected one", w.Code)
			}
		})
	}
}

// C3: If-Match must name the stored route digest, after the revision check.
func TestRoutePutIfMatch(t *testing.T) {
	seed := manifest(t, 5, "")
	d := routes.Digest(seed)
	stored := hex.EncodeToString(d[:])
	other := strings.Repeat("0", 64)
	cases := []struct {
		name     string
		revision int
		ifMatch  string
		want     int
	}{
		{"absent 204", 6, "", http.StatusNoContent},
		{"match 204", 6, stored, http.StatusNoContent},
		{"mismatch 412", 6, other, http.StatusPreconditionFailed},
		{"stale revision before mismatch 409", 5, other, http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteFixture(t, inMemoryStore(t))
			if err := f.store.ReplaceRoutes(routes.Envelope{Manifest: seed, Token: "seed"}, 5, ""); err != nil {
				t.Fatal(err)
			}
			b := manifest(t, tc.revision, "")
			w := f.putIfMatch(t, b, sign(t, f.signer, http.MethodPut, routes.Path, b), tc.ifMatch)
			if w.Code != tc.want {
				t.Fatalf("PUT /routes If-Match %q = %d, want %d; body=%s", tc.ifMatch, w.Code, tc.want, w.Body)
			}
			if ct := w.Header().Get("Content-Type"); tc.want == http.StatusPreconditionFailed && !strings.HasPrefix(ct, "text/plain") {
				t.Fatalf("412 Content-Type = %q, want text/plain", ct)
			}
		})
	}
}

// O8 via W1: a CDS without operator keys refuses route writes, whether the
// authorizer is unset or the one run wires when --operator-keys is empty.
func TestRoutePutWithoutOperatorKeys(t *testing.T) {
	store := inMemoryStore(t)
	f := newRouteFixture(t, store)
	b := manifest(t, 1, "")
	auth := sign(t, f.signer, http.MethodPut, routes.Path, b)
	for name, authorize := range map[string]allowlist.WriteAuthorizer{
		"nil":      nil,
		"disabled": operatorauth.Verifier{}.Authorize,
	} {
		t.Run(name, func(t *testing.T) {
			h := routeHandler{Store: store, Authorize: authorize, MeshCA: f.meshCA}
			req := httptest.NewRequest(http.MethodPut, routes.Path, bytes.NewReader(b))
			req.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			h.handlePut(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("PUT /routes = %d, want 401", w.Code)
			}
		})
	}
}

func TestRouteGetNotFound(t *testing.T) {
	f := newRouteFixture(t, inMemoryStore(t))
	if w := f.get(t); w.Code != http.StatusNotFound {
		t.Fatalf("GET /routes = %d, want 404", w.Code)
	}
}

// C1, C2: GET serves the PUT bytes and token verbatim in the two-member
// envelope, and the envelope verifies as W2 requires.
func TestRoutePutThenGetRoundTrips(t *testing.T) {
	f := newRouteFixture(t, inMemoryStore(t))
	// Formatting a re-serializer would change: indentation and member order.
	b := []byte("{\n  \"revision\": 3, \"schema\": \"c8s.routes/v1\",\n  \"notBefore\": \"2026-09-01T00:00:00Z\", \"maxAgeSeconds\": 60, \"hosts\": {}\n}\n")
	auth := sign(t, f.signer, http.MethodPut, routes.Path, b)
	if w := f.put(t, b, auth); w.Code != http.StatusNoContent {
		t.Fatalf("PUT /routes = %d, want 204; body=%s", w.Code, w.Body)
	}

	w := f.get(t)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /routes = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var members map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &members); err != nil || len(members) != 2 {
		t.Fatalf("envelope = %s, want exactly manifest and token", w.Body)
	}
	var env routes.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !bytes.Equal(env.Manifest, b) {
		t.Fatalf("served manifest = %q, want %q", env.Manifest, b)
	}
	if want := strings.TrimPrefix(auth, "Bearer "); env.Token != want {
		t.Fatalf("served token = %q, want %q", env.Token, want)
	}
	if _, err := routes.VerifySigned(env, []*ecdsa.PublicKey{f.key}, nil); err != nil {
		t.Fatalf("VerifySigned(served envelope) = %v", err)
	}
}

// C4: concurrent writes of one revision cannot both land.
func TestRoutePutConcurrentSameRevision(t *testing.T) {
	f := newRouteFixture(t, inMemoryStore(t))
	const writers = 8
	bodies := make([][]byte, writers)
	auths := make([]string, writers)
	for i := range bodies {
		// Same revision, distinct bytes, so the stored one names its writer.
		bodies[i] = bytes.Replace(manifest(t, 1, ""), []byte(`"vllm"`), []byte(fmt.Sprintf(`"vllm-%d"`, i)), 1)
		auths[i] = sign(t, f.signer, http.MethodPut, routes.Path, bodies[i])
	}
	codes := make([]int, writers)
	var wg sync.WaitGroup
	for i := range bodies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = f.put(t, bodies[i], auths[i]).Code
		}()
	}
	wg.Wait()

	winner := -1
	for i, c := range codes {
		switch c {
		case http.StatusNoContent:
			if winner >= 0 {
				t.Fatalf("codes = %v, want one 204", codes)
			}
			winner = i
		case http.StatusConflict:
		default:
			t.Fatalf("codes = %v, want one 204 and the rest 409", codes)
		}
	}
	if winner < 0 {
		t.Fatalf("codes = %v, want one 204", codes)
	}
	got, err := f.store.LoadRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Manifest, bodies[winner]) {
		t.Fatalf("stored manifest is not the 204 writer's")
	}
}

// C5: with a persistent database file, a CDS restart keeps the manifest and
// its revision floor.
func TestRoutesSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	open := func() *allowlist.Store {
		s, err := allowlist.OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		return &s
	}
	first := open()
	f := newRouteFixture(t, first)
	b := manifest(t, 2, "")
	if w := f.put(t, b, sign(t, f.signer, http.MethodPut, routes.Path, b)); w.Code != http.StatusNoContent {
		t.Fatalf("PUT /routes = %d, want 204", w.Code)
	}
	before := f.get(t).Body.String()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := open()
	t.Cleanup(func() { _ = second.Close() })
	g := newRouteFixture(t, second)
	if w := g.get(t); w.Code != http.StatusOK || w.Body.String() != before {
		t.Fatalf("GET /routes after restart = %d %s, want 200 %s", w.Code, w.Body, before)
	}
	stale := manifest(t, 2, "")
	if w := g.put(t, stale, sign(t, g.signer, http.MethodPut, routes.Path, stale)); w.Code != http.StatusConflict {
		t.Fatalf("PUT /routes revision 2 after restart = %d, want 409", w.Code)
	}
}

func TestRouteHandlersReturn500OnStoreFailure(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	f := newRouteFixture(t, &store)
	if w := f.get(t); w.Code != http.StatusInternalServerError {
		t.Fatalf("GET /routes = %d, want 500", w.Code)
	}
	b := manifest(t, 1, "")
	if w := f.put(t, b, sign(t, f.signer, http.MethodPut, routes.Path, b)); w.Code != http.StatusInternalServerError {
		t.Fatalf("PUT /routes = %d, want 500", w.Code)
	}
}

// C3 cannot run its mesh-CA check without the mesh CA, so writes fail closed,
// after authorization.
func TestRoutePutWithoutMeshCA(t *testing.T) {
	store := inMemoryStore(t)
	f := newRouteFixture(t, store)
	h := routeHandler{Store: store, Authorize: func(*http.Request, []byte) error { return nil }}
	b := manifest(t, 1, f.otherPEM)
	w := httptest.NewRecorder()
	h.handlePut(w, httptest.NewRequest(http.MethodPut, routes.Path, bytes.NewReader(b)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("PUT /routes without a mesh CA = %d, want 500", w.Code)
	}
	if _, err := store.LoadRoutes(); err == nil {
		t.Fatal("a manifest was stored without the mesh CA check")
	}

	unauthenticated := routeHandler{Store: store, Authorize: func(*http.Request, []byte) error { return errors.New("no token") }}
	w = httptest.NewRecorder()
	unauthenticated.handlePut(w, httptest.NewRequest(http.MethodPut, routes.Path, bytes.NewReader(b)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PUT /routes without a mesh CA = %d, want 401", w.Code)
	}
}
