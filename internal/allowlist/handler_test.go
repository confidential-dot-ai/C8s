package allowlist_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	digestA       = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	digestMissing = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// testOperatorCredential generates an operator key pair: a Signer for minting
// write tokens and the public key CDS would pin.
func testOperatorCredential(t *testing.T) (*operatorauth.Signer, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen operator key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal operator key: %v", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("new operator signer: %v", err)
	}
	return signer, &key.PublicKey
}

// authHeader mints an operator token bound to method + path + body and returns
// it as an Authorization header value. Callers MUST pass the exact method, path,
// and bytes the server will receive — any difference breaks the token's bindings.
func authHeader(t *testing.T, signer *operatorauth.Signer, method, path string, body []byte) string {
	t.Helper()
	header, err := signer.Authorization(method, path, body)
	if err != nil {
		t.Fatalf("mint operator token: %v", err)
	}
	return header
}

func testAllowlistApp(t *testing.T) (http.Handler, *readiness.Checker, *operatorauth.Signer) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}

	signer, pub := testOperatorCredential(t)

	asClient := remote.NewClient("http://localhost:0")
	checker := readiness.NewChecker(asClient, 10*time.Second)

	// Writes authorize through the production operatorauth.Verifier, so these
	// tests exercise the same auth path a deployment runs.
	wh := allowlist.Handler{
		Store:           &store,
		WriteAuthorizer: operatorauth.Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}.Authorize,
	}

	return allowlistTestRouter(wh, checker.Ready), &checker, signer
}

// allowlistTestRouter mounts the allowlist routes on a chi router so the
// workload path parameter resolves the same way the cds router serves it.
func allowlistTestRouter(wh allowlist.Handler, ready attestation.ReadinessFunc) http.Handler {
	r := chi.NewRouter()
	r.Get("/readyz", attestation.HandleReadyz(ready))
	r.Get("/allowlist", wh.HandleList)
	r.Put("/allowlist", wh.HandleReplaceAll)
	r.Put("/allowlist/workloads/{name}", wh.HandlePutWorkload)
	r.Delete("/allowlist/workloads/{name}", wh.HandleDeleteWorkload)
	return r
}

// getAllowlist fetches and parses the served document.
func getAllowlist(t *testing.T, srvURL string) *pkgallowlist.Allowlist {
	t.Helper()
	resp, err := http.Get(srvURL + "/allowlist")
	if err != nil {
		t.Fatalf("get allowlist: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get allowlist: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	al, err := pkgallowlist.ParseJSON(body)
	if err != nil {
		t.Fatalf("parse served allowlist: %v; body=%s", err, body)
	}
	return al
}

// servedETag reads the ETag of the served document, the version a reader sees.
func servedETag(t *testing.T, srvURL string) string {
	t.Helper()
	resp, err := http.Get(srvURL + "/allowlist")
	if err != nil {
		t.Fatalf("get allowlist: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get allowlist: status %d", resp.StatusCode)
	}
	return resp.Header.Get("ETag")
}

// wantUnchanged asserts a refused write left the served document at the ETag
// read before it and created no entry of the given name.
func wantUnchanged(t *testing.T, srvURL, etag, absentName string) {
	t.Helper()
	if got := servedETag(t, srvURL); got != etag {
		t.Fatalf("a refused write changed the version: ETag %q, was %q", got, etag)
	}
	if _, ok := getAllowlist(t, srvURL).Workloads[absentName]; ok {
		t.Fatalf("a refused write created the entry %q", absentName)
	}
}

func TestReadyzReturnsUnavailableInitially(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want 503", resp.StatusCode)
	}
}

func TestAllowlistListEmpty(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	al := getAllowlist(t, srv.URL)
	if al.Schema != pkgallowlist.Schema {
		t.Fatalf("schema = %q, want %q", al.Schema, pkgallowlist.Schema)
	}
	if len(al.Workloads) != 0 {
		t.Fatalf("expected empty workloads, got %d entries", len(al.Workloads))
	}
}

func TestAllowlistReplaceRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()
	etag := servedETag(t, srv.URL)

	body := fmt.Sprintf(`{"schema":%q,"workloads":{"web":{"containers":[{"digest":"%s"}]}}}`, pkgallowlist.Schema, digestA)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
	wantUnchanged(t, srv.URL, etag, "web")
}

// TestAllowlistReplaceSwapsSet verifies PUT is a full replace: an entry present
// before the replace and absent from the new document is gone afterward.
func TestAllowlistReplaceSwapsSet(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	putWorkload(t, srv.URL, signer, "old", digestA)

	putBody := fmt.Sprintf(`{"schema":%q,"workloads":{"new":{"containers":[{"digest":"%s"}]}}}`, pkgallowlist.Schema, digestMissing)
	putReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, "/allowlist", []byte(putBody)))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: got %d, want 204", putResp.StatusCode)
	}

	al := getAllowlist(t, srv.URL)
	if len(al.Workloads) != 1 {
		t.Fatalf("expected exactly 1 entry after replace, got %d", len(al.Workloads))
	}
	if w, ok := al.Workloads["new"]; !ok || w.Containers[0].Digest.String() != digestMissing {
		t.Fatalf("replaced set missing new entry: %#v", al.Workloads)
	}
	if _, ok := al.Workloads["old"]; ok {
		t.Fatal("old entry survived a full replace")
	}
}

// guardTestHandler builds a Handler with a permissive authorizer, for tests of
// the post-auth request-decoding guards.
func guardTestHandler(t *testing.T) (allowlist.Handler, *allowlist.Store) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	h := allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}
	return h, &store
}

// TestAllowlistReplaceRejectsInvalidDoc pins that PUT validates via ParseJSON:
// a body without the schema field (or otherwise malformed) is 422 and does not
// touch the store.
func TestAllowlistReplaceRejectsInvalidDoc(t *testing.T) {
	h, store := guardTestHandler(t)
	if err := store.PutWorkload("web", entryFor(t, digestA)); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	_, versionBefore, _ := store.LoadAll()

	// The last body is the pre-unification shape: a top-level digests map is
	// an unknown field now and must be refused rather than silently dropped.
	for _, body := range []string{`{}`, `{"workloads":{}}`, `{"schema":"other","workloads":{}}`,
		`{"schema":"c8s.allowlist/v1","digests":{"` + digestA + `":"img"}}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
		h.HandleReplaceAll(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("PUT %s: got status %d, want 422", body, rec.Code)
		}
	}

	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(doc.Workloads) != 1 || version != versionBefore {
		t.Fatalf("invalid PUT must not change the allowlist: %d entries, version %s -> %s",
			len(doc.Workloads), versionBefore, version)
	}
}

// TestAllowlistReplaceExplicitEmptyClears verifies a valid empty document clears
// the allowlist.
func TestAllowlistReplaceExplicitEmptyClears(t *testing.T) {
	h, store := guardTestHandler(t)
	if err := store.PutWorkload("web", entryFor(t, digestA)); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"schema":%q,"workloads":{}}`, pkgallowlist.Schema)
	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
	h.HandleReplaceAll(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want 204", rec.Code)
	}

	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(doc.Workloads) != 0 {
		t.Fatalf("explicit empty replace left %d entries", len(doc.Workloads))
	}
}

// entryFor is a minimally-specified one-container entry at digest.
func entryFor(t *testing.T, digest string) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: d}}}
}

// workloadRequest builds a request for the per-entry handlers with the chi
// {name} parameter resolved, as the cds router would.
func workloadRequest(method, name, body string) *http.Request {
	req := httptest.NewRequest(method, "/allowlist/workloads/"+name, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", name)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// putWorkload writes a one-container entry through the signed PUT path.
func putWorkload(t *testing.T, srvURL string, signer *operatorauth.Signer, name, digest string) {
	t.Helper()
	path := "/allowlist/workloads/" + name
	body := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digest)
	req, err := http.NewRequest(http.MethodPut, srvURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, path, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put workload got status %d, want 204", resp.StatusCode)
	}
}

// TestWorkloadPutRejectsUnpinnedOperatorKey proves a well-formed token signed
// by a key CDS does not pin is rejected at the handler level.
func TestWorkloadPutRejectsUnpinnedOperatorKey(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()
	etag := servedETag(t, srv.URL)

	otherSigner, _ := testOperatorCredential(t) // not the pinned key
	path := "/allowlist/workloads/web"
	body := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestA)
	req, err := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, otherSigner, http.MethodPut, path, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
	wantUnchanged(t, srv.URL, etag, "web")
}

// TestWorkloadPutRejectsReplayWithDifferentBody: a captured operator token for
// one body MUST NOT authorize a different body within the token's TTL.
func TestWorkloadPutRejectsReplayWithDifferentBody(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()
	etag := servedETag(t, srv.URL)

	path := "/allowlist/workloads/web"
	originalBody := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestA)
	header := authHeader(t, signer, http.MethodPut, path, []byte(originalBody))

	attackerBody := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestMissing)
	req, err := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(attackerBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("captured token authorized a different body: got status %d, want 401", resp.StatusCode)
	}
	wantUnchanged(t, srv.URL, etag, "web")
}

// TestWorkloadPutRejectsTokenBeyondMaxValidity: a token stamped with a lifetime
// longer than the verifier's MaxTokenValidity is refused whatever the signer
// chose, and refusing it changes nothing.
func TestWorkloadPutRejectsTokenBeyondMaxValidity(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()
	etag := servedETag(t, srv.URL)

	path := "/allowlist/workloads/web"
	body := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestA)
	req, err := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer.WithTTL(time.Hour), http.MethodPut, path, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("hour-long token authorized a write: got status %d, want 401", resp.StatusCode)
	}
	wantUnchanged(t, srv.URL, etag, "web")
}

// TestWorkloadPutRejectsBodyOverConfiguredCap confirms the per-Handler cap is
// honoured: an over-cap body returns 413 before the auth check runs.
func TestWorkloadPutRejectsBodyOverConfiguredCap(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	signer, pub := testOperatorCredential(t)
	asClient := remote.NewClient("http://localhost:0")
	checker := readiness.NewChecker(asClient, 10*time.Second)
	wh := allowlist.Handler{
		Store:             &store,
		WriteAuthorizer:   operatorauth.Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}.Authorize,
		MaxWriteBodyBytes: 64,
	}
	srv := httptest.NewServer(allowlistTestRouter(wh, checker.Ready))
	defer srv.Close()

	path := "/allowlist/workloads/web"
	body := strings.Repeat("x", 1024)
	req, err := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, path, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body got status %d, want 413", resp.StatusCode)
	}
}

// TestAllowlistDefaultWriteBodyCap pins the built-in cap applied when
// MaxWriteBodyBytes is unset: a normal mutation body passes, one over 64 KiB
// is rejected before decoding.
func TestAllowlistDefaultWriteBodyCap(t *testing.T) {
	h, _ := guardTestHandler(t)

	small := fmt.Sprintf(`{"containers":[{"digest":%q}]}`, digestA)
	rec := httptest.NewRecorder()
	h.HandlePutWorkload(rec, workloadRequest(http.MethodPut, "web", small))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("small body got status %d, want 204 (body %q)", rec.Code, rec.Body.String())
	}

	big := strings.Repeat("x", 64*1024+1)
	rec = httptest.NewRecorder()
	h.HandlePutWorkload(rec, workloadRequest(http.MethodPut, "web", big))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body got status %d, want 413", rec.Code)
	}
}

// TestWorkloadPutDeleteRoundtrip exercises the workload routes end to end,
// including the {name} path parameter and the 404 on a repeated delete.
func TestWorkloadPutDeleteRoundtrip(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	path := "/allowlist/workloads/web"
	body := fmt.Sprintf(`{"label":"web","containers":[{"digest":"%s"}]}`, digestA)
	putReq, _ := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, path, []byte(body)))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: got %d, want 204", putResp.StatusCode)
	}

	al := getAllowlist(t, srv.URL)
	w, ok := al.Workloads["web"]
	if !ok || len(w.Containers) != 1 || w.Containers[0].Digest.String() != digestA {
		t.Fatalf("served workload = %#v", al.Workloads)
	}

	del := func() int {
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+path, nil)
		req.Header.Set("Authorization", authHeader(t, signer, http.MethodDelete, path, nil))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := del(); code != http.StatusNoContent {
		t.Fatalf("first delete: got %d, want 204", code)
	}
	etag := servedETag(t, srv.URL)
	if code := del(); code != http.StatusNotFound {
		t.Fatalf("second delete: got %d, want 404", code)
	}
	if got := servedETag(t, srv.URL); got != etag {
		t.Fatalf("a 404 delete changed the version: ETag %q, was %q", got, etag)
	}
}

func TestWorkloadPutRejectsInvalidBody(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	path := "/allowlist/workloads/web"
	body := `{"containers":[{"digest":"sha256:bad"}]}`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, path, []byte(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid workload body: got %d, want 422", resp.StatusCode)
	}
}

func TestWorkloadPutRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()
	etag := servedETag(t, srv.URL)

	body := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestA)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/allowlist/workloads/web", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth workload put: got %d, want 401", resp.StatusCode)
	}
	wantUnchanged(t, srv.URL, etag, "web")
}

func TestAllowlistListEmitsETag(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"1"` {
		t.Fatalf("ETag = %q, want W/\"1\"", got)
	}
}

func TestAllowlistListMatchingIfNoneMatchReturns304(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/allowlist", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", `W/"1"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"1"` {
		t.Fatalf("ETag = %q, want W/\"1\"", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("304 body should be empty, got %d bytes", len(body))
	}
}

func TestAllowlistListStaleIfNoneMatchReturns200WithNewETag(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	putWorkload(t, srv.URL, signer, "web", digestA)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/allowlist", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", `W/"1"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"2"` {
		t.Fatalf("ETag = %q, want W/\"2\"", got)
	}
}

// TestAllowlistWritesRejectedWithoutAuthorizer pins the fail-closed default:
// a Handler wired without a WriteAuthorizer refuses every mutation.
func TestAllowlistWritesRejectedWithoutAuthorizer(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	h := allowlist.Handler{Store: &store}

	body := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestA)
	rec := httptest.NewRecorder()
	h.HandlePutWorkload(rec, workloadRequest(http.MethodPut, "web", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("PUT without authorizer: got status %d, want 401", rec.Code)
	}
}

// TestAllowlistMutationsRejectMalformedBody covers the decode guards on every
// mutation: syntactically invalid JSON and unknown fields both 422.
func TestAllowlistMutationsRejectMalformedBody(t *testing.T) {
	h, _ := guardTestHandler(t)

	cases := []struct {
		name    string
		handler http.HandlerFunc
		body    string
	}{
		{"put invalid json", h.HandlePutWorkload, `{`},
		{"put unknown field", h.HandlePutWorkload, `{"containers":[{"digest":"` + digestA + `"}],"bogus":1}`},
		{"replace invalid json", h.HandleReplaceAll, `{`},
		{"replace unknown field", h.HandleReplaceAll, `{"workloads":{},"bogus":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, workloadRequest(http.MethodPut, "web", tc.body))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("got status %d, want 422", rec.Code)
			}
		})
	}
}

// TestAllowlistHandlersReturn500OnStoreFailure drives every handler against a
// store whose DB is closed, so the storage layer errors surface as 500s.
func TestAllowlistHandlersReturn500OnStoreFailure(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	h := allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
	}{
		{"list", h.HandleList, http.MethodGet, ""},
		{"put", h.HandlePutWorkload, http.MethodPut, fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestA)},
		{"delete", h.HandleDeleteWorkload, http.MethodDelete, ""},
		{"replace", h.HandleReplaceAll, http.MethodPut, fmt.Sprintf(`{"schema":"c8s.allowlist/v1","workloads":{"web":{"containers":[{"digest":"%s"}]}}}`, digestA)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, workloadRequest(tc.method, "web", tc.body))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("got status %d, want 500", rec.Code)
			}
		})
	}
}
