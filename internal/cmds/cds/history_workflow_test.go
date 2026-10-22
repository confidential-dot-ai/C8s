package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// TestOperatorChangePolicyWorkflow runs the documented P → P∪Q → Q change
// against CDS's router, wired as run.go wires it: signed whole-document PUTs,
// the journal started before serving, and single-use operator tokens.
func TestOperatorChangePolicyWorkflow(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	keys := []*ecdsa.PublicKey{&key.PublicKey}
	mesh, err := issuer.NewMeshCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newRouter(dependencies{
		AttestHandler: AttestHandler{CertTTL: time.Hour},
		AllowlistHandler: allowlist.Handler{
			Store:           &store,
			WriteAuthorizer: singleUse(operatorauth.Verifier{Keys: keys, ClockSkew: time.Second}.AuthorizeIssuedAt, &store, time.Time{}, 0),
		},
		ReadyFn:          func() bool { return true },
		MeshCA:           mesh,
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}))
	t.Cleanup(srv.Close)

	entry := func(digest string) pkgallowlist.Workload {
		return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{
			Digest:  wlDigest(t, digest),
			Command: anyPolicy,
			Args:    anyPolicy,
		}}}
	}
	doc := func(workloads map[string]pkgallowlist.Workload) []byte {
		raw, err := (&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		// ParseJSON fills the defaults CDS stores, as the CLI's loaders do.
		parsed, err := pkgallowlist.ParseJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := parsed.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return canonical
	}
	p := doc(map[string]pkgallowlist.Workload{"app": entry("sha256:" + strings.Repeat("a", 64))})
	pq := doc(map[string]pkgallowlist.Workload{
		"app":    entry("sha256:" + strings.Repeat("a", 64)),
		"app-v2": entry("sha256:" + strings.Repeat("b", 64)),
	})
	q := doc(map[string]pkgallowlist.Workload{"app-v2": entry("sha256:" + strings.Repeat("b", 64))})

	put := func(body []byte, authorization string) int {
		req, err := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", authorization)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get := func(path string) (int, []byte) {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, b
	}

	for _, body := range [][]byte{p, pq, q} {
		authorization, err := signer.Authorization(http.MethodPut, "/allowlist", body)
		if err != nil {
			t.Fatal(err)
		}
		if code := put(body, authorization); code != http.StatusNoContent {
			t.Fatalf("PUT /allowlist = %d, want 204", code)
		}
	}

	code, raw := get("/allowlist/history")
	if code != http.StatusOK {
		t.Fatalf("GET /allowlist/history = %d, want 200", code)
	}
	var history struct {
		Entries []allowlist.HistoryEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &history); err != nil {
		t.Fatal(err)
	}
	// Position 1 is the empty document CDS served at start.
	if len(history.Entries) != 4 {
		t.Fatalf("history has %d entries, want the start document then P, P∪Q, Q: %s", len(history.Entries), raw)
	}
	published := history.Entries[1:]
	for i, want := range [][]byte{p, pq, q} {
		e := published[i]
		sum := sha256.Sum256(want)
		hexDigest := hex.EncodeToString(sum[:])
		if e.Digest != "sha256:"+hexDigest || !e.Signed || e.Position != int64(i+2) {
			t.Fatalf("history entry %d = %+v, want signed sha256:%s at position %d", i, e, hexDigest, i+2)
		}
		code, object := get("/allowlist/objects/sha256/" + hexDigest)
		if code != http.StatusOK || !bytes.Equal(object, want) {
			t.Fatalf("GET object %d = %d %q, want 200 and the uploaded bytes", i, code, object)
		}
		if got := sha256.Sum256(object); hex.EncodeToString(got[:]) != hexDigest {
			t.Fatalf("object %d does not hash to its digest", i)
		}
		code, token := get("/allowlist/objects/sha256/" + hexDigest + "/signature")
		if code != http.StatusOK {
			t.Fatalf("GET signature %d = %d, want 200", i, code)
		}
		if err := operatorauth.VerifyStored(keys, string(token), http.MethodPut, "/allowlist", object); err != nil {
			t.Fatalf("VerifyStored(signature %d) = %v", i, err)
		}
	}

	// P's signature is public; replaying it must not roll the allowlist back to P.
	_, pToken := get("/allowlist/objects/sha256/" + strings.TrimPrefix(published[0].Digest, "sha256:") + "/signature")
	if code := put(p, "Bearer "+string(pToken)); code != http.StatusConflict {
		t.Fatalf("PUT /allowlist with P's stored token = %d, want 409", code)
	}
	if code, served := get("/allowlist"); code != http.StatusOK || !bytes.Equal(served, q) {
		t.Fatalf("GET /allowlist after replay = %d %q, want Q", code, served)
	}
	if _, raw := get("/allowlist/history"); !bytes.Contains(raw, []byte(published[2].Digest)) || bytes.Count(raw, []byte(`"position"`)) != 4 {
		t.Fatalf("history changed after a rejected replay: %s", raw)
	}
}
