package allowlist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func openJournaled(t *testing.T) *Store {
	t.Helper()
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.StartJournal(); err != nil {
		t.Fatalf("StartJournal: %v", err)
	}
	return &store
}

// servedDigest is the digest of the bytes GET /allowlist serves now.
func servedDigest(t *testing.T, store *Store) (string, string) {
	t.Helper()
	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	body, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return objectDigest(body), version
}

func canonicalDoc(t *testing.T, workloads map[string]pkgallowlist.Workload) []byte {
	t.Helper()
	raw, err := (&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// ParseJSON fills the defaults the store keeps, as the CLI's loaders do.
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

func TestHistoryRecordsEachServedDocument(t *testing.T) {
	store := openJournaled(t)
	a := map[string]pkgallowlist.Workload{"a": oneContainerWorkload(mustParseDigest(t, digestA))}
	empty := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{}}

	steps := []struct {
		name   string
		mutate func() error
		grows  bool
	}{
		{"put", func() error { return store.PutWorkload("a", a["a"]) }, true},
		{"identical put", func() error { return store.PutWorkload("a", a["a"]) }, false},
		{"identical replace", func() error {
			al, err := pkgallowlist.ParseJSON(canonicalDoc(t, a))
			if err != nil {
				return err
			}
			return store.ReplaceAll(al)
		}, false},
		{"seed", func() error {
			_, err := store.SeedWorkloads(map[string]pkgallowlist.Workload{"b": oneContainerWorkload(mustParseDigest(t, digestB))})
			return err
		}, true},
		{"seed adding nothing", func() error {
			_, err := store.SeedWorkloads(map[string]pkgallowlist.Workload{"b": oneContainerWorkload(mustParseDigest(t, digestC))})
			return err
		}, false},
		{"delete", func() error { _, err := store.DeleteWorkload("a"); return err }, true},
		{"delete of an absent entry", func() error { _, err := store.DeleteWorkload("a"); return err }, false},
		{"revert to the first document", func() error { return store.ReplaceAll(empty) }, true},
	}

	want, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 1 {
		t.Fatalf("history after StartJournal = %+v, want the served document only", want)
	}
	for _, step := range steps {
		if err := step.mutate(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if step.grows {
			digest, version := servedDigest(t, store)
			want = append(want, HistoryEntry{Position: int64(len(want) + 1), Version: version, Digest: digest})
		}
		got, err := store.History()
		if err != nil {
			t.Fatalf("%s: History: %v", step.name, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: history has %d entries, want %d: %+v", step.name, len(got), len(want), got)
		}
		head, wantHead := got[len(got)-1], want[len(want)-1]
		if head.Position != wantHead.Position || head.Version != wantHead.Version || head.Digest != wantHead.Digest || head.Signed {
			t.Errorf("%s: head = %+v, want %+v", step.name, head, wantHead)
		}
		if time.Since(head.PublishedAt) > time.Minute {
			t.Errorf("%s: published_at = %s, want now", step.name, head.PublishedAt)
		}
	}
	got, _ := store.History()
	if got[0].Digest != got[len(got)-1].Digest {
		t.Errorf("revert digest %s, want the first document's %s", got[len(got)-1].Digest, got[0].Digest)
	}
	for _, e := range got {
		body, ok, err := store.Object(e.Digest)
		if err != nil || !ok || objectDigest(body) != e.Digest {
			t.Errorf("Object(%s) = %d bytes, %v, %v; want bytes hashing to the digest", e.Digest, len(body), ok, err)
		}
	}
}

func TestStartJournalAfterSeedAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SeedWorkloads(map[string]pkgallowlist.Workload{"a": oneContainerWorkload(mustParseDigest(t, digestA))}); err != nil {
		t.Fatal(err)
	}
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	seeded, _ := servedDigest(t, &store)
	store.Close()

	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	got, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Position != 1 || got[0].Digest != seeded {
		t.Fatalf("history = %+v, want the seeded document %s at position 1 only", got, seeded)
	}
}

func TestStartJournalRefusesCorruptHistory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate string
	}{
		{"tampered object", "UPDATE journal_object SET body = CAST(REPLACE(CAST(body AS TEXT), 'workloads', 'workloadz') AS BLOB)"},
		{"missing object", "DELETE FROM journal_object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := openJournaled(t)
			if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(tc.mutate); err != nil {
				t.Fatal(err)
			}
			if err := store.StartJournal(); err == nil {
				t.Fatal("StartJournal over a corrupt history succeeded, want an error")
			}
		})
	}
}

// Object serves only history entries whose bytes still hash to their digest.
func TestObjectRefusesUnservedOrTampered(t *testing.T) {
	store := openJournaled(t)
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	head := mustHistory(t, store)[1].Digest
	stray := objectDigest([]byte("{}"))
	if _, err := store.db.Exec("INSERT INTO journal_object (digest, body) VALUES (?, ?)", stray, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if body, ok, err := store.Object(stray); ok || err != nil {
		t.Errorf("Object(never served) = %q, %v, %v; want not found", body, ok, err)
	}
	if _, err := store.db.Exec("UPDATE journal_object SET body = CAST('{}' AS BLOB) WHERE digest = ?", head); err != nil {
		t.Fatal(err)
	}
	if body, ok, err := store.Object(head); ok || err == nil {
		t.Errorf("Object(tampered) = %q, %v, %v; want an error", body, ok, err)
	}
}

func TestSignPolicyOnlyForCanonicalWholeDocument(t *testing.T) {
	store := openJournaled(t)
	h := Handler{Store: store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}
	put := func(body, token string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.HandleReplaceAll(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("PUT /allowlist = %d: %s", w.Code, w.Body)
		}
	}
	canonical := canonicalDoc(t, map[string]pkgallowlist.Workload{"a": oneContainerWorkload(mustParseDigest(t, digestA))})
	digest := objectDigest(canonical)

	put(" "+string(canonical), "padded")
	if _, ok, _ := store.Signature(digest); ok {
		t.Fatal("a non-canonical body stored a signature")
	}
	put(string(canonical), "signed")
	if token, ok, err := store.Signature(digest); err != nil || !ok || token != "signed" {
		t.Fatalf("Signature(%s) = %q, %v, %v; want the write token", digest, token, ok, err)
	}
	if err := store.SignPolicy([]byte(`{"schema":"other"}`), "stray"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Signature(objectDigest([]byte(`{"schema":"other"}`))); ok {
		t.Fatal("SignPolicy stored a signature for a document never served")
	}

	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); err != nil {
		t.Fatal(err)
	}
	got, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	var signed []bool
	for _, e := range got {
		signed = append(signed, e.Signed)
	}
	if want := []bool{false, true, false}; !slices.Equal(signed, want) {
		t.Fatalf("signed = %v, want %v (empty, PUT /allowlist, per-workload put)", signed, want)
	}
}

// A write whose signature cannot be stored reports failure, and re-uploading
// the same document signs it.
func TestReplaceAllReportsUnstoredSignature(t *testing.T) {
	store := openJournaled(t)
	h := Handler{Store: store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}
	canonical := canonicalDoc(t, map[string]pkgallowlist.Workload{"a": oneContainerWorkload(mustParseDigest(t, digestA))})
	put := func(token string) int {
		r := httptest.NewRequest(http.MethodPut, "/allowlist", bytes.NewReader(canonical))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.HandleReplaceAll(w, r)
		return w.Code
	}

	if _, err := store.db.Exec("ALTER TABLE journal_signature RENAME TO broken"); err != nil {
		t.Fatal(err)
	}
	if code := put("first"); code != http.StatusInternalServerError {
		t.Fatalf("PUT /allowlist with the signature unstored = %d, want 500", code)
	}
	if _, err := store.db.Exec("ALTER TABLE broken RENAME TO journal_signature"); err != nil {
		t.Fatal(err)
	}
	if code := put("second"); code != http.StatusNoContent {
		t.Fatalf("re-upload = %d, want 204", code)
	}
	if token, ok, err := store.Signature(objectDigest(canonical)); err != nil || !ok || token != "second" {
		t.Fatalf("Signature = %q, %v, %v; want the re-upload's token", token, ok, err)
	}
}

func TestConsumeToken(t *testing.T) {
	store := openJournaled(t)
	for _, first := range []string{"t1", "h.p1.s1"} {
		if err := store.ConsumeToken(first); err != nil {
			t.Fatalf("ConsumeToken(%q) first use = %v", first, err)
		}
	}
	for _, reuse := range []string{"t1", "h.p1.s1", "h.p1.s2"} {
		if err := store.ConsumeToken(reuse); !errors.Is(err, ErrTokenReused) {
			t.Fatalf("ConsumeToken(%q) = %v, want ErrTokenReused", reuse, err)
		}
	}
	if err := store.ConsumeToken("h.p2.s1"); err != nil {
		t.Fatalf("ConsumeToken(other payload) = %v, want accepted", err)
	}
}

func TestReusedTokenIsConflict(t *testing.T) {
	h := Handler{Store: openJournaled(t), WriteAuthorizer: func(*http.Request, []byte) error { return ErrTokenReused }}
	w := httptest.NewRecorder()
	h.HandleReplaceAll(w, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader("{}")))
	if w.Code != http.StatusConflict {
		t.Fatalf("PUT /allowlist with a reused token = %d, want 409", w.Code)
	}
}

func TestTokenBeforeStartIsExplained(t *testing.T) {
	h := Handler{Store: openJournaled(t), WriteAuthorizer: func(*http.Request, []byte) error {
		return fmt.Errorf("%w: detail", ErrTokenBeforeStart)
	}}
	w := httptest.NewRecorder()
	h.HandleReplaceAll(w, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader("{}")))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ErrTokenBeforeStart.Error()) {
		t.Fatalf("PUT /allowlist with a pre-start token = %d %q, want 401 naming ErrTokenBeforeStart", w.Code, w.Body.String())
	}
}

func TestHistoryRoutes(t *testing.T) {
	store := openJournaled(t)
	canonical := canonicalDoc(t, map[string]pkgallowlist.Workload{"a": oneContainerWorkload(mustParseDigest(t, digestA))})
	al, err := pkgallowlist.ParseJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAll(al); err != nil {
		t.Fatal(err)
	}
	if err := store.SignPolicy(canonical, "tok"); err != nil {
		t.Fatal(err)
	}
	empty, _, _ := store.Object(mustHistory(t, store)[0].Digest)
	hexOf := func(b []byte) string { return strings.TrimPrefix(objectDigest(b), "sha256:") }

	h := Handler{Store: store}
	r := chi.NewRouter()
	r.Get("/allowlist/history", h.HandleHistory)
	r.Get("/allowlist/objects/sha256/{hex}", h.HandleObject)
	r.Get("/allowlist/objects/sha256/{hex}/signature", h.HandleSignature)

	for _, tc := range []struct {
		name, path  string
		code        int
		contentType string
		body        []byte
	}{
		{"object", "/allowlist/objects/sha256/" + hexOf(canonical), 200, "application/json", canonical},
		{"signature", "/allowlist/objects/sha256/" + hexOf(canonical) + "/signature", 200, "text/plain", []byte("tok")},
		{"unsigned", "/allowlist/objects/sha256/" + hexOf(empty) + "/signature", 404, "", nil},
		{"unknown object", "/allowlist/objects/sha256/" + strings.Repeat("0", 64), 404, "", nil},
		{"uppercase hex", "/allowlist/objects/sha256/" + strings.ToUpper(hexOf(canonical)), 400, "", nil},
		{"short hex", "/allowlist/objects/sha256/abc/signature", 400, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != tc.code {
				t.Fatalf("GET %s = %d, want %d", tc.path, w.Code, tc.code)
			}
			if tc.body == nil {
				return
			}
			if ct := w.Header().Get("Content-Type"); ct != tc.contentType {
				t.Errorf("Content-Type = %q, want %q", ct, tc.contentType)
			}
			if !bytes.Equal(w.Body.Bytes(), tc.body) {
				t.Errorf("body = %s, want %s", w.Body, tc.body)
			}
		})
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/allowlist/history", nil))
	var got struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 {
		t.Fatalf("GET /allowlist/history = %d %s: %v", w.Code, w.Body, err)
	}
	if len(got.Entries) != 2 || got.Entries[1]["digest"] != objectDigest(canonical) || got.Entries[1]["signed"] != true ||
		got.Entries[0]["position"] != 1.0 || got.Entries[0]["signed"] != false {
		t.Fatalf("history = %s, want the empty then the signed document", w.Body)
	}
	if _, err := time.Parse(time.RFC3339, got.Entries[0]["published_at"].(string)); err != nil {
		t.Errorf("published_at: %v", err)
	}
}

func mustHistory(t *testing.T, store *Store) []HistoryEntry {
	t.Helper()
	got, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	return got
}
