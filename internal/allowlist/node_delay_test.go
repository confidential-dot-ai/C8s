package allowlist

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Nodes get a document only once it has been the newest for the node delay;
// one superseded sooner never reaches them, and the database's first document
// is served at once. Everyone else gets the newest.
func TestServedToNodesWaitsOutTheDelay(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	store.SetNodeDelay(30 * time.Second)
	t0 := time.Now().Add(-25 * time.Second)
	apply := func(cmd Command, at time.Time) {
		t.Helper()
		cmd.AtMS = at.UnixMilli()
		if err := store.Apply(cmd).Err(sentinels); err != nil {
			t.Fatalf("%s: %v", cmd.Op, err)
		}
	}
	doc := func(digest string) *pkgallowlist.Allowlist {
		al, err := pkgallowlist.ParseJSON(canonicalDoc(t, map[string]pkgallowlist.Workload{"a": oneContainerWorkload(mustParseDigest(t, digest))}))
		if err != nil {
			t.Fatal(err)
		}
		return al
	}
	nodes := func(now time.Time) string {
		t.Helper()
		body, _, err := store.ServedToNodes(now)
		if err != nil {
			t.Fatal(err)
		}
		return objectDigest(body)
	}

	apply(Command{Op: OpStartJournal}, t0)
	seed := nodes(t0)
	apply(Command{Op: OpReplaceAll, Allowlist: doc(digestA)}, t0.Add(time.Second))
	apply(Command{Op: OpReplaceAll, Allowlist: doc(digestB)}, t0.Add(11*time.Second))
	newest, _, err := store.Served()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		at    time.Duration
		want  string
		depth int
	}{
		{"before the newest survives", 40 * time.Second, seed, 3},
		{"once the newest survives", 41 * time.Second, objectDigest(newest), 1},
	} {
		if got := nodes(t0.Add(tc.at)); got != tc.want {
			t.Errorf("%s: nodes served %s, want %s", tc.name, got, tc.want)
		}
		if depth, err := store.NodeServedDepth(t0.Add(tc.at)); err != nil || depth != tc.depth {
			t.Errorf("%s: NodeServedDepth = %d, %v, want %d", tc.name, depth, err, tc.depth)
		}
	}

	h := Handler{Allowlist: store.Local()}
	for query, want := range map[string]string{"": objectDigest(newest), "?" + pkgallowlist.NodeQuery: seed} {
		w := httptest.NewRecorder()
		h.HandleList(w, httptest.NewRequest(http.MethodGet, "/allowlist"+query, nil))
		if w.Code != http.StatusOK || objectDigest(w.Body.Bytes()) != want {
			t.Errorf("GET /allowlist%s = %d %s, want %s", query, w.Code, objectDigest(w.Body.Bytes()), want)
		}
	}
}
