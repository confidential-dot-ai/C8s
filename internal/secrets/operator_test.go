package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorHarness wires the handler to a real store and a recording authorizer,
// so a test can assert on what the authorizer was handed as well as on the
// response.
type operatorHarness struct {
	h        OperatorHandler
	store    *MemoryStore
	seenBody []byte
	authErr  error
}

func newOperatorHarness(t *testing.T) *operatorHarness {
	t.Helper()
	oh := &operatorHarness{store: NewMemoryStore(8, 7, 64)}
	oh.h = OperatorHandler{
		Store: oh.store,
		Authorize: func(_ *http.Request, body []byte) error {
			oh.seenBody = append([]byte(nil), body...)
			return oh.authErr
		},
	}
	return oh
}

// setStore swaps in a store bounded for the test at hand, keeping the
// harness's own view and the handler's the same one.
func (oh *operatorHarness) setStore(s *MemoryStore) {
	oh.store, oh.h.Store = s, s
}

// errorCode reads the machine-readable code out of a refusal envelope.
func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error envelope %q: %v", w.Body.String(), err)
	}
	return resp.Error
}

func putRequest(t *testing.T, path string, value []byte, overwrite bool) *http.Request {
	t.Helper()
	body, err := json.Marshal(PutRequest{
		Value:     base64.StdEncoding.EncodeToString(value),
		Overwrite: overwrite,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPut, "/secrets"+path, bytes.NewReader(body))
}

func doPut(h OperatorHandler, r *http.Request) (*httptest.ResponseRecorder, PutResponse) {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var resp PutResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func TestOperatorPutCreates(t *testing.T) {
	oh := newOperatorHarness(t)
	w, resp := doPut(oh.h, putRequest(t, "/tenant-a/db", []byte("hunter2"), false))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body)
	}
	if !resp.Created || resp.Existing != "" {
		t.Fatalf("resp = %+v, want a bare creation", resp)
	}
	got, err := oh.store.Get(context.Background(), "/tenant-a/db")
	if err != nil || !bytes.Equal(got, []byte("hunter2")) {
		t.Fatalf("stored %q %v", got, err)
	}
}

// The whole point of the create-first shape: a path holding a value is reported
// back untouched, so the operator sees what a replacement would destroy before
// it happens.
func TestOperatorPutRefusesToDisplaceWithoutOverwrite(t *testing.T) {
	oh := newOperatorHarness(t)
	ctx := context.Background()
	if _, _, err := oh.store.PutIfAbsent(ctx, "/tenant-a/db", []byte("generated"), WorkloadHolder("api")); err != nil {
		t.Fatal(err)
	}

	w, resp := doPut(oh.h, putRequest(t, "/tenant-a/db", []byte("hunter2"), false))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if resp.Created || resp.Existing != OriginWorkload {
		t.Fatalf("resp = %+v, want the workload origin", resp)
	}
	got, _ := oh.store.Get(ctx, "/tenant-a/db")
	if !bytes.Equal(got, []byte("generated")) {
		t.Fatalf("a refused write changed the value to %q", got)
	}
}

// A 409 names what put the value there and nothing else: the value itself must
// never reach a write-only caller.
func TestOperatorPutConflictWithholdsTheValue(t *testing.T) {
	oh := newOperatorHarness(t)
	if _, _, err := oh.store.PutIfAbsent(context.Background(), "/a", []byte("topsecret"), WorkloadHolder("api")); err != nil {
		t.Fatal(err)
	}
	w, _ := doPut(oh.h, putRequest(t, "/a", []byte("new"), false))
	if strings.Contains(w.Body.String(), "topsecret") ||
		strings.Contains(w.Body.String(), base64.StdEncoding.EncodeToString([]byte("topsecret"))) {
		t.Fatalf("the conflict response carried the stored value: %s", w.Body)
	}
}

func TestOperatorPutOverwriteReplaces(t *testing.T) {
	oh := newOperatorHarness(t)
	ctx := context.Background()
	if _, _, err := oh.store.PutIfAbsent(ctx, "/a", []byte("generated"), WorkloadHolder("api")); err != nil {
		t.Fatal(err)
	}

	w, resp := doPut(oh.h, putRequest(t, "/a", []byte("chosen"), true))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body)
	}
	if resp.Created || resp.Existing != OriginWorkload {
		t.Fatalf("resp = %+v, want the displaced workload origin", resp)
	}
	got, _ := oh.store.Get(ctx, "/a")
	if !bytes.Equal(got, []byte("chosen")) {
		t.Fatalf("value = %q, want the operator's", got)
	}
}

// An overwrite onto an empty path is a creation, not a replacement, so the CLI
// does not claim to have destroyed something that was never there.
func TestOperatorPutOverwriteOnEmptyPathCreates(t *testing.T) {
	oh := newOperatorHarness(t)
	w, resp := doPut(oh.h, putRequest(t, "/a", []byte("chosen"), true))
	if w.Code != http.StatusCreated || !resp.Created || resp.Existing != "" {
		t.Fatalf("status = %d resp = %+v, want a plain creation", w.Code, resp)
	}
}

// Overwrite intent rides in the body so the operator token's pbh claim covers
// it; a query parameter would be outside both htu and pbh.
func TestOperatorPutAuthorizesTheExactBody(t *testing.T) {
	oh := newOperatorHarness(t)
	req := putRequest(t, "/a", []byte("v"), true)
	body, _ := json.Marshal(PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("v")), Overwrite: true})
	doPut(oh.h, req)
	if !bytes.Equal(oh.seenBody, body) {
		t.Fatalf("authorizer saw %q, want the exact request body %q", oh.seenBody, body)
	}
}

func TestOperatorPutRejectsUnauthorized(t *testing.T) {
	oh := newOperatorHarness(t)
	oh.authErr = fmt.Errorf("no token")
	w, _ := doPut(oh.h, putRequest(t, "/a", []byte("v"), false))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if oh.store.Len() != 0 {
		t.Fatal("an unauthorized request reached the store")
	}
}

// Nil means no operator keys are pinned, which must reject rather than admit.
func TestOperatorPutWithoutAuthorizerRejects(t *testing.T) {
	h := OperatorHandler{Store: NewMemoryStore(8, 7, 64)}
	w, _ := doPut(h, putRequest(t, "/a", []byte("v"), false))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// Authorization runs before the path is parsed, so an unauthenticated caller
// cannot even learn which paths are well-formed.
func TestOperatorPutChecksAuthBeforeThePath(t *testing.T) {
	oh := newOperatorHarness(t)
	oh.authErr = fmt.Errorf("no token")
	req := httptest.NewRequest(http.MethodPut, "/secrets/../etc", strings.NewReader(`{"value":"AA=="}`))
	w := httptest.NewRecorder()
	oh.h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 rather than a path error", w.Code)
	}
}

func TestOperatorPutRejectsBadRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body string
		want int
	}{
		{"uncanonical path", "/secrets/a/../b", `{"value":"dg=="}`, http.StatusBadRequest},
		{"percent-encoded path", "/secrets/a%2Fb", `{"value":"dg=="}`, http.StatusBadRequest},
		{"trailing slash", "/secrets/a/", `{"value":"dg=="}`, http.StatusBadRequest},
		{"outside the prefix", "/other/a", `{"value":"dg=="}`, http.StatusBadRequest},
		{"unknown field", "/secrets/a", `{"value":"dg==","ttl":5}`, http.StatusUnprocessableEntity},
		{"not json", "/secrets/a", `nonsense`, http.StatusUnprocessableEntity},
		{"value not base64", "/secrets/a", `{"value":"not base64!"}`, http.StatusUnprocessableEntity},
		{"empty value", "/secrets/a", `{"value":""}`, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oh := newOperatorHarness(t)
			req := httptest.NewRequest(http.MethodPut, tc.path, strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			oh.h.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body)
			}
			if oh.store.Len() != 0 {
				t.Fatal("a rejected request reached the store")
			}
		})
	}
}

func TestOperatorPutCapsTheBody(t *testing.T) {
	oh := newOperatorHarness(t)
	oh.h.MaxBodyBytes = 16
	req := putRequest(t, "/a", bytes.Repeat([]byte("x"), 64), false)
	w := httptest.NewRecorder()
	oh.h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
}

// The store's per-value bound is a fail-closed limit on process memory, so
// exceeding it is a server error rather than a silent truncation.
func TestOperatorPutRespectsTheStoreValueBound(t *testing.T) {
	oh := newOperatorHarness(t)
	w, _ := doPut(oh.h, putRequest(t, "/a", bytes.Repeat([]byte("x"), 65), false))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if oh.store.Len() != 0 {
		t.Fatal("an oversized value was stored")
	}
}

// A full store is the operator's own sizing, so it answers 507 naming the
// ceiling; an existing path can still be replaced.
func TestOperatorPutAtTheCeilingIsInsufficientStorage(t *testing.T) {
	oh := newOperatorHarness(t)
	oh.setStore(NewMemoryStore(2, 1, 64))

	for _, p := range []string{"/a", "/b"} {
		if w, _ := doPut(oh.h, putRequest(t, p, []byte("first"), false)); w.Code != http.StatusCreated {
			t.Fatalf("put %s = %d, want 201", p, w.Code)
		}
	}
	w, _ := doPut(oh.h, putRequest(t, "/c", []byte("second"), false))
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("put at the ceiling = %d, want 507", w.Code)
	}
	if code := errorCode(t, w); code != types.ErrorCodeSecretStoreFull {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeSecretStoreFull)
	}
	if oh.store.Len() != 2 {
		t.Fatalf("store holds %d paths after a refusal, want 2", oh.store.Len())
	}
	if w, _ := doPut(oh.h, putRequest(t, "/a", []byte("replaced"), true)); w.Code != http.StatusOK {
		t.Fatalf("replacing an existing path at the ceiling = %d, want 200", w.Code)
	}
}

func TestOperatorPutStoreFailureIsFiveHundred(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		h := OperatorHandler{
			Store:     failingStore{err: fmt.Errorf("backend down")},
			Authorize: func(*http.Request, []byte) error { return nil },
		}
		w, _ := doPut(h, putRequest(t, "/a", []byte("v"), overwrite))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("overwrite=%v: status = %d, want 500", overwrite, w.Code)
		}
	}
}

// --- against the real operator credential ---

// The claim the body-bound token makes has to hold against the real verifier,
// not just a stub: a captured write must not be replayable against another path,
// and must not be editable into an overwrite.
func TestOperatorPutAgainstRealOperatorAuth(t *testing.T) {
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
	store := NewMemoryStore(8, 7, 64)
	h := OperatorHandler{
		Store:     store,
		Authorize: operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&key.PublicKey}}.Authorize,
	}

	create, _ := json.Marshal(PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("v1"))})
	authz, err := signer.Authorization(http.MethodPut, "/secrets/a", create)
	if err != nil {
		t.Fatal(err)
	}
	send := func(path string, body []byte, header string) int {
		req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
		req.Header.Set("Authorization", header)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if code := send("/secrets/a", create, authz); code != http.StatusCreated {
		t.Fatalf("a properly signed write = %d, want 201", code)
	}
	if code := send("/secrets/b", create, authz); code != http.StatusUnauthorized {
		t.Fatalf("the same token against another path = %d, want 401", code)
	}

	// Editing the captured body into an overwrite breaks the pbh binding, which
	// is why the flag rides in the body rather than the query string.
	escalated, _ := json.Marshal(PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("v1")), Overwrite: true})
	if code := send("/secrets/a", escalated, authz); code != http.StatusUnauthorized {
		t.Fatalf("an edited body = %d, want 401", code)
	}
	if code := send("/secrets/a", create, authz); code != http.StatusConflict {
		t.Fatalf("replaying the create = %d, want 409 (nothing displaced)", code)
	}
	got, _ := store.Get(context.Background(), "/a")
	if !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("value = %q, want the one write that was authorized", got)
	}
}
