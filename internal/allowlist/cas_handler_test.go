package allowlist_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

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

func TestAllowlistReplaceIfMatch(t *testing.T) {
	h, store := guardTestHandler(t)
	if err := store.PutWorkload("web", entryFor(t, digestA)); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	_, version, _ := store.LoadAll()
	doc := func(digest string) string {
		return fmt.Sprintf(`{"schema":%q,"workloads":{"new":{"containers":[{"digest":"%s"}]}}}`, pkgallowlist.Schema, digest)
	}

	// Refused preconditions: an older version, the weak ETag GET serves (strong
	// comparison never matches a weak tag), an unquoted value.
	for _, ifMatch := range []string{`"1"`, `W/"` + version + `"`, version, `"` + version + `0"`} {
		if code := putAllowlistIfMatch(t, h, doc(digestMissing), ifMatch); code != http.StatusPreconditionFailed {
			t.Fatalf("If-Match %s: got %d, want 412", ifMatch, code)
		}
		al, after, _ := store.LoadAll()
		if after != version || len(al.Workloads) != 1 || al.Workloads["web"].Containers == nil {
			t.Fatalf("If-Match %s: a refused precondition changed the store (version %s -> %s, %v)", ifMatch, version, after, al.Workloads)
		}
	}

	if code := putAllowlistIfMatch(t, h, doc(digestMissing), `"`+version+`"`); code != http.StatusNoContent {
		t.Fatalf("current version: got %d, want 204", code)
	}
	al, next, _ := store.LoadAll()
	if _, ok := al.Workloads["new"]; !ok || next == version {
		t.Fatalf("matching If-Match did not replace: version %s, %v", next, al.Workloads)
	}
	// The version it matched is gone: a second write built on it is refused.
	if code := putAllowlistIfMatch(t, h, doc(digestA), `"`+version+`"`); code != http.StatusPreconditionFailed {
		t.Fatalf("stale version after a write: got %d, want 412", code)
	}
	for _, ifMatch := range []string{"", "*"} {
		if code := putAllowlistIfMatch(t, h, doc(digestA), ifMatch); code != http.StatusNoContent {
			t.Fatalf("If-Match %q: got %d, want an unconditional 204", ifMatch, code)
		}
	}
}
