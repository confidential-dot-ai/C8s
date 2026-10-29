package allowlist_test

import (
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

// allowlistTestRouter mounts the allowlist routes on a chi router, as the cds
// router serves them.
func allowlistTestRouter(wh allowlist.Handler, ready attestation.ReadinessFunc) http.Handler {
	r := chi.NewRouter()
	r.Get("/readyz", attestation.HandleReadyz(ready))
	r.Get("/allowlist", wh.HandleList)
	r.Put("/allowlist", wh.HandleReplaceAll)
	return r
}

// getServed fetches the served document and the ETag it was served with.
func getServed(t *testing.T, srvURL string) (*pkgallowlist.Allowlist, string) {
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
	return al, resp.Header.Get("ETag")
}

// getAllowlist fetches and parses the served document.
func getAllowlist(t *testing.T, srvURL string) *pkgallowlist.Allowlist {
	t.Helper()
	al, _ := getServed(t, srvURL)
	return al
}

// servedETag reads the ETag of the served document, the version a reader sees.
func servedETag(t *testing.T, srvURL string) string {
	t.Helper()
	_, etag := getServed(t, srvURL)
	return etag
}

// wantUnchanged asserts the served document still carries etag. Every write
// that changes the document bumps its version, so an equal ETag means the
// refusal changed nothing.
func wantUnchanged(t *testing.T, srvURL, etag string) {
	t.Helper()
	if got := servedETag(t, srvURL); got != etag {
		t.Fatalf("a refused write changed the version: ETag %q, was %q", got, etag)
	}
}

// refusedWrite sends req, asserts the 401 a refused write answers, and asserts
// the served document is as it was before.
func refusedWrite(t *testing.T, srvURL string, req *http.Request) {
	t.Helper()
	etag := servedETag(t, srvURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
	wantUnchanged(t, srvURL, etag)
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

	body := fmt.Sprintf(`{"schema":%q,"workloads":{"web":{"containers":[{"digest":"%s"}]}}}`, pkgallowlist.Schema, digestA)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	refusedWrite(t, srv.URL, req)
}

// TestAllowlistReplaceSwapsSet verifies PUT is a full replace: an entry present
// before the replace and absent from the new document is gone afterward.
func TestAllowlistReplaceSwapsSet(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	writeEntry(t, srv.URL, signer, "old", digestA)

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

// putAllowlistIfMatch sends a whole document with the given If-Match ("" sends
// none) and returns the status.
func putAllowlistIfMatch(t *testing.T, h allowlist.Handler, body, ifMatch string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	h.HandleReplaceAll(rec, req)
	return rec.Code
}

// A write conditional on the version it was built from lands only while CDS
// still serves that version, so it never overwrites a write made since.
func TestAllowlistReplaceIfMatch(t *testing.T) {
	h, store := guardTestHandler(t)
	seedEntry(t, store, "web", digestA)
	_, version, _ := store.LoadAll()

	// Refused preconditions: an older version, the weak ETag GET serves
	// (strong comparison never matches a weak tag), an unquoted value.
	for _, ifMatch := range []string{`"1"`, `W/"` + version + `"`, version, `"` + version + `0"`, "*"} {
		if code := putAllowlistIfMatch(t, h, oneEntryDocument("new", digestMissing), ifMatch); code != http.StatusPreconditionFailed {
			t.Fatalf("If-Match %s: got %d, want 412", ifMatch, code)
		}
		al, after, _ := store.LoadAll()
		if after != version || len(al.Workloads) != 1 || al.Workloads["web"].Containers == nil {
			t.Fatalf("If-Match %s: a refused precondition changed the store (version %s -> %s, %v)", ifMatch, version, after, al.Workloads)
		}
	}

	if code := putAllowlistIfMatch(t, h, oneEntryDocument("new", digestMissing), `"`+version+`"`); code != http.StatusNoContent {
		t.Fatalf("current version: got %d, want 204", code)
	}
	al, next, _ := store.LoadAll()
	if _, ok := al.Workloads["new"]; !ok || next == version {
		t.Fatalf("matching If-Match did not replace: version %s, %v", next, al.Workloads)
	}
	// The version it matched is gone: a second write built on it is refused.
	if code := putAllowlistIfMatch(t, h, oneEntryDocument("new", digestA), `"`+version+`"`); code != http.StatusPreconditionFailed {
		t.Fatalf("stale version after a write: got %d, want 412", code)
	}
	if code := putAllowlistIfMatch(t, h, oneEntryDocument("new", digestA), ""); code != http.StatusNoContent {
		t.Fatalf("no If-Match: got %d, want an unconditional 204", code)
	}
}

// A precondition no version can satisfy is refused before the write is
// authorized, so it does not spend the operator's one-shot token.
func TestAllowlistReplaceRefusesUnmatchableIfMatchBeforeAuth(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	spent := false
	h := allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error {
		spent = true
		return nil
	}}

	if code := putAllowlistIfMatch(t, h, oneEntryDocument("web", digestA), `W/"1"`); code != http.StatusPreconditionFailed {
		t.Fatalf("weak If-Match: got %d, want 412", code)
	}
	if spent {
		t.Fatal("the write was authorized, spending a token, before the precondition was refused")
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
	seedEntry(t, store, "web", digestA)
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
	seedEntry(t, store, "web", digestA)

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

// seedEntry makes the stored allowlist the document holding one named entry
// at digest.
func seedEntry(t *testing.T, store *allowlist.Store, name, digest string) {
	t.Helper()
	d, err := types.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	doc := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{name: {Containers: []pkgallowlist.Container{{Digest: d}}}},
	}
	if err := store.ReplaceAll(doc, allowlist.OperatorWrite{}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
}

// oneEntryDocument is the allowlist document holding one named entry at
// digest.
func oneEntryDocument(name, digest string) string {
	return fmt.Sprintf(`{"schema":%q,"workloads":{%q:{"containers":[{"digest":%q}]}}}`, pkgallowlist.Schema, name, digest)
}

// replaceRequest builds a PUT of the whole document; a nil signer sends it
// without a token.
func replaceRequest(t *testing.T, srvURL string, signer *operatorauth.Signer, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, srvURL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if signer != nil {
		req.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, "/allowlist", []byte(body)))
	}
	return req
}

// writeEntry makes the allowlist the document holding one named entry,
// through the signed write path.
func writeEntry(t *testing.T, srvURL string, signer *operatorauth.Signer, name, digest string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(replaceRequest(t, srvURL, signer, oneEntryDocument(name, digest)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("write got status %d, want 204", resp.StatusCode)
	}
}

// TestReplaceRejectsUnpinnedOperatorKey proves a well-formed token signed by a
// key CDS does not pin is rejected at the handler level.
func TestReplaceRejectsUnpinnedOperatorKey(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	otherSigner, _ := testOperatorCredential(t) // not the pinned key
	refusedWrite(t, srv.URL, replaceRequest(t, srv.URL, otherSigner, oneEntryDocument("web", digestA)))
}

// TestReplaceRejectsReplayWithDifferentBody: a captured operator token for one
// document MUST NOT authorize a different one within the token's TTL.
func TestReplaceRejectsReplayWithDifferentBody(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	signed := oneEntryDocument("web", digestA)
	attackerBody := oneEntryDocument("web", digestMissing)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", strings.NewReader(attackerBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, "/allowlist", []byte(signed)))
	refusedWrite(t, srv.URL, req)
}

// TestReplaceRejectsTokenBeyondMaxValidity: a token stamped with a lifetime
// longer than the verifier's MaxTokenValidity is refused whatever the signer
// chose, and refusing it changes nothing.
func TestReplaceRejectsTokenBeyondMaxValidity(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	refusedWrite(t, srv.URL, replaceRequest(t, srv.URL, signer.WithTTL(time.Hour), oneEntryDocument("web", digestA)))
}

// TestReplaceRejectsBodyOverConfiguredCap confirms the per-Handler cap is
// honoured: an over-cap body returns 413 before the auth check runs.
func TestReplaceRejectsBodyOverConfiguredCap(t *testing.T) {
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

	body := strings.Repeat("x", 1024)
	req := replaceRequest(t, srv.URL, signer, body)

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

	rec := httptest.NewRecorder()
	h.HandleReplaceAll(rec, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(oneEntryDocument("web", digestA))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("small body got status %d, want 204 (body %q)", rec.Code, rec.Body.String())
	}

	big := strings.Repeat("x", 64*1024+1)
	rec = httptest.NewRecorder()
	h.HandleReplaceAll(rec, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(big)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body got status %d, want 413", rec.Code)
	}
}

// A document whose entry is not valid is refused whole: the write is signed
// over bytes CDS will not serve.
func TestReplaceRejectsInvalidEntry(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"schema":%q,"workloads":{"web":{"containers":[{"digest":"sha256:bad"}]}}}`, pkgallowlist.Schema)
	resp, err := http.DefaultClient.Do(replaceRequest(t, srv.URL, signer, body))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid entry in the document: got %d, want 422", resp.StatusCode)
	}
}

// An entry name the allowlist grammar refuses is refused with the document,
// so no write puts one in the store.
func TestReplaceRejectsInvalidEntryName(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.DefaultClient.Do(replaceRequest(t, srv.URL, signer, oneEntryDocument("bad/name", digestA)))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("entry name with a slash: got %d, want 422", resp.StatusCode)
	}
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

	writeEntry(t, srv.URL, signer, "web", digestA)

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

	rec := httptest.NewRecorder()
	h.HandleReplaceAll(rec, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(oneEntryDocument("web", digestA))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("PUT without authorizer: got status %d, want 401", rec.Code)
	}
}

// TestAllowlistWriteRejectsMalformedBody covers the decode guards on a write:
// syntactically invalid JSON and unknown fields both 422.
func TestAllowlistWriteRejectsMalformedBody(t *testing.T) {
	h, _ := guardTestHandler(t)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"invalid json", `{`},
		{"unknown field", `{"workloads":{},"bogus":1}`},
		{"unknown entry field", `{"schema":"c8s.allowlist/v1","workloads":{"web":{"containers":[{"digest":"` + digestA + `"}],"bogus":1}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.HandleReplaceAll(rec, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(tc.body)))
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

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
	}{
		{"list", h.HandleList, http.MethodGet, ""},
		{"replace", h.HandleReplaceAll, http.MethodPut, oneEntryDocument("web", digestA)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, httptest.NewRequest(tc.method, "/allowlist", strings.NewReader(tc.body)))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("got status %d, want 500", rec.Code)
			}
		})
	}
}
