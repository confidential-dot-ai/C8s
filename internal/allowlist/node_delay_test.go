package allowlist

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A write takes effect on nodes the node delay after it is written, one
// replaced before then never does, and the first allowlist takes effect at
// once. Everyone else reads the newest.
func TestInEffectWaitsOutTheDelay(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	store.SetNodeDelay(30 * time.Second)
	doc := func(digest string) *pkgallowlist.Allowlist {
		al, err := pkgallowlist.ParseJSON(canonicalDoc(t, map[string]pkgallowlist.Workload{"a": oneContainerWorkload(mustParseDigest(t, digest))}))
		if err != nil {
			t.Fatal(err)
		}
		return al
	}
	nodes := func(now time.Time) string {
		t.Helper()
		body, _, err := store.InEffect(now)
		if err != nil {
			t.Fatal(err)
		}
		return objectDigest(body)
	}

	if err := store.StartJournal(); err != nil {
		t.Fatal(err)
	}
	seed := nodes(time.Now())
	for _, digest := range []string{digestA, digestB} {
		if err := store.ReplaceAll(doc(digest), OperatorWrite{}); err != nil {
			t.Fatal(err)
		}
	}
	written := time.Now()
	newest, _, err := store.Served()
	if err != nil {
		t.Fatal(err)
	}

	if got := nodes(written); got != seed {
		t.Errorf("before the newest write takes effect: nodes served %s, want the seed %s", got, seed)
	}
	if got := nodes(written.Add(31 * time.Second)); got != objectDigest(newest) {
		t.Errorf("once the newest write takes effect: nodes served %s, want %s", got, objectDigest(newest))
	}

	h := Handler{Store: &store}
	for query, want := range map[string]string{"": objectDigest(newest), "?" + pkgallowlist.NodeQuery: seed} {
		w := httptest.NewRecorder()
		h.HandleList(w, httptest.NewRequest(http.MethodGet, "/allowlist"+query, nil))
		if w.Code != http.StatusOK || objectDigest(w.Body.Bytes()) != want {
			t.Errorf("GET /allowlist%s = %d %s, want %s", query, w.Code, objectDigest(w.Body.Bytes()), want)
		}
	}
}
