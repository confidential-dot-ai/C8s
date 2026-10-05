package allowlist

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestJournalBound(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 0); err != nil {
		t.Fatalf("start journal: %v", err)
	}
	genesis, err := store.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	steps := []struct {
		name      string
		mutate    func() error
		boundSize int
		drain     bool
	}{
		{"addition", func() error { return store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))) }, 1, false},
		{"second addition", func() error { return store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))) }, 1, false},
		{"removal", func() error { _, err := store.DeleteWorkload("a"); return err }, 2, true},
		{"re-addition of a bound policy", func() error { return store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))) }, 2, false},
		{"addition while draining", func() error { return store.PutWorkload("c", oneContainerWorkload(mustParseDigest(t, digestC))) }, 3, false},
		{"modified entry", func() error {
			return store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestA)))
		}, 4, true},
		{"identical write", func() error {
			return store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestA)))
		}, 4, false},
	}
	prev := genesis
	for _, step := range steps {
		if err := step.mutate(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		st, err := store.State()
		if err != nil {
			t.Fatalf("%s: state: %v", step.name, err)
		}
		if len(st.Bound) != step.boundSize || !slices.Contains(st.Bound, st.Policy) {
			t.Errorf("%s: bound = %v, want %d distinct entries including %s", step.name, st.Bound, step.boundSize, st.Policy)
		}
		if step.name == "identical write" {
			if st.Head != prev.Head {
				t.Errorf("%s: head moved to %s", step.name, st.Head)
			}
			continue
		}

		body, ok, err := store.Object(st.Head)
		if err != nil || !ok {
			t.Fatalf("%s: head object: ok=%v err=%v", step.name, ok, err)
		}
		var ev Event
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Fatalf("%s: decode head: %v", step.name, err)
		}
		if ev.Parent != prev.Head || ev.Source != prev.Policy || ev.Target != st.Policy || ev.DrainRequired != step.drain || ev.Authority != "sha256:auth" {
			t.Errorf("%s: event = %+v, want parent %s source %s drain %v", step.name, ev, prev.Head, prev.Policy, step.drain)
		}
		if _, ok, _ := store.Object(st.Policy); !ok {
			t.Errorf("%s: policy object %s missing", step.name, st.Policy)
		}
		prev = st
	}
}

func TestJournalLeaseStagesAndLocks(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 10*time.Second); err != nil {
		t.Fatalf("start journal: %v", err)
	}
	_, before, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}

	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatalf("put: %v", err)
	}
	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Workloads) != 0 || version != before {
		t.Fatalf("staged write is enforced: workloads %v, version %s (was %s)", doc.Workloads, version, before)
	}
	st, err := store.State()
	if err != nil {
		t.Fatal(err)
	}
	if st.Pending != st.Policy || st.Lease != 10 {
		t.Fatalf("state = %+v, want pending %s and a 10s lease", st, st.Policy)
	}

	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); !errors.Is(err, ErrUpdatePending) {
		t.Fatalf("second write = %v, want ErrUpdatePending", err)
	}
	h := Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}
	w := httptest.NewRecorder()
	h.HandleReplaceAll(w, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(`{"schema":"`+pkgallowlist.Schema+`","workloads":{}}`)))
	if w.Code != http.StatusConflict {
		t.Fatalf("PUT /allowlist while pending = %d, want 409: %s", w.Code, w.Body)
	}
	if ok, err := store.Activate(time.Now()); ok || err != nil {
		t.Fatalf("Activate before the lease = %v, %v; want false, nil", ok, err)
	}
	if ok, err := store.Activate(time.Now().Add(11 * time.Second)); !ok || err != nil {
		t.Fatalf("Activate after the lease = %v, %v; want true, nil", ok, err)
	}

	doc, version, err = store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Workloads["a"]; !ok || version == before {
		t.Fatalf("activated document = %v at version %s, want entry a at a new version", doc.Workloads, version)
	}
	if st, _ := store.State(); st.Pending != "" || st.Version != version {
		t.Fatalf("state after activation = %+v, want no pending and version %s", st, version)
	}
	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); err != nil {
		t.Fatalf("write after activation: %v", err)
	}
}

// A restart without a lease activates an update an earlier run staged.
func TestJournalPendingSurvivesLeaseRemoval(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}

	staged, err := store.State()
	if err != nil {
		t.Fatal(err)
	}

	if err := store.StartJournal("sha256:auth", 0); err != nil {
		t.Fatal(err)
	}
	restarted, err := store.State()
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Position != staged.Position || restarted.Head != staged.Head || restarted.Pending != staged.Pending {
		t.Fatalf("state after restart = %+v, want the staged state %+v", restarted, staged)
	}
	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); !errors.Is(err, ErrUpdatePending) {
		t.Fatalf("write over a pending update without a lease = %v, want ErrUpdatePending", err)
	}
	if ok, err := store.Activate(time.Now()); !ok || err != nil {
		t.Fatalf("Activate without a lease = %v, %v; want true, nil", ok, err)
	}
	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Workloads["a"]; !ok {
		t.Fatalf("activated document = %v, want the staged entry a", doc.Workloads)
	}
	if version != staged.Version {
		t.Fatalf("activated version = %s, want the published %s", version, staged.Version)
	}
}

func TestJournalReplayRefusesBrokenChain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate string
	}{
		{"tampered event", "UPDATE journal_object SET body = CAST(REPLACE(CAST(body AS TEXT), 'published', 'drained') AS BLOB) WHERE digest = (SELECT digest FROM journal_event WHERE position = 1)"},
		{"dropped event", "DELETE FROM journal_event WHERE position = 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := OpenInMemory()
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer store.Close()
			if err := store.StartJournal("sha256:auth", 0); err != nil {
				t.Fatal(err)
			}
			for name, d := range map[string]string{"a": digestA, "b": digestB} {
				if err := store.PutWorkload(name, oneContainerWorkload(mustParseDigest(t, d))); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.db.Exec(tc.mutate); err != nil {
				t.Fatal(err)
			}
			store.gen++
			if st, err := store.State(); err == nil {
				t.Fatalf("State() over a broken chain = %+v, want an error", st)
			}
		})
	}
}

func headEvent(t *testing.T, store *Store, st State) Event {
	t.Helper()
	body, ok, err := store.Object(st.Head)
	if err != nil || !ok {
		t.Fatalf("head object: ok=%v err=%v", ok, err)
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// A narrowing widens the bound; Drain on the enforced policy appends a
// drained event and collapses it, and only then.
func TestJournalDrain(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Activate(time.Now().Add(11 * time.Second)); !ok || err != nil {
		t.Fatalf("activate addition = %v, %v", ok, err)
	}
	if _, err := store.DeleteWorkload("a"); err != nil {
		t.Fatal(err)
	}
	widened, err := store.State()
	if err != nil {
		t.Fatal(err)
	}
	if len(widened.Bound) != 2 || widened.Pending != widened.Policy {
		t.Fatalf("state after a narrowing = %+v, want a 2-entry bound and a pending target", widened)
	}
	if ok, err := store.Drain(widened.Policy, []string{"10.0.0.1"}); ok || err != nil {
		t.Fatalf("Drain while the narrowing is pending = %v, %v; want false", ok, err)
	}
	if ok, err := store.Activate(time.Now().Add(30 * time.Second)); !ok || err != nil {
		t.Fatalf("activate narrowing = %v, %v", ok, err)
	}
	if ok, err := store.Drain(widened.Bound[0], nil); ok || err != nil {
		t.Fatalf("Drain on a policy that is not enforced = %v, %v; want false", ok, err)
	}
	if ok, err := store.Drain(widened.Policy, []string{"10.0.0.1"}); !ok || err != nil {
		t.Fatalf("Drain on the enforced policy = %v, %v; want true", ok, err)
	}
	st, err := store.State()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(st.Bound, []string{widened.Policy}) || st.Position != widened.Position+1 {
		t.Fatalf("drained state = %+v, want bound [%s] at position %d", st, widened.Policy, widened.Position+1)
	}
	ev := headEvent(t, &store, st)
	if ev.Type != EventDrained || ev.Parent != widened.Head || ev.Target != widened.Policy || ev.Authority != "sha256:auth" || !slices.Equal(ev.Nodes, []string{"10.0.0.1"}) {
		t.Fatalf("drained event = %+v, want a drained event on %s chained to %s", ev, widened.Policy, widened.Head)
	}
	if ok, err := store.Drain(widened.Policy, []string{"10.0.0.1"}); ok || err != nil {
		t.Fatalf("second Drain = %v, %v; want false (already drained)", ok, err)
	}

	// The next narrowing widens the drained bound again.
	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Activate(time.Now().Add(time.Hour)); !ok || err != nil {
		t.Fatalf("activate = %v, %v", ok, err)
	}
	if _, err := store.DeleteWorkload("b"); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.State(); len(st.Bound) != 2 {
		t.Fatalf("bound after a narrowing over a drained bound = %v, want 2 entries", st.Bound)
	}
}

// A canonical whole-document write records its token as the policy's
// signature; a non-canonical body or a per-workload write records none.
func TestJournalSignsCanonicalReplace(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 0); err != nil {
		t.Fatal(err)
	}
	h := Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}
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
	doc := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{
		"a": oneContainerWorkload(mustParseDigest(t, digestA)),
	}}
	raw, err := doc.Canonical()
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
	put(string(canonical), "signed")
	digest := objectDigest(canonical)
	if token, ok, err := store.Signature(digest); err != nil || !ok || token != "signed" {
		t.Fatalf("Signature(%s) = %q, %v, %v; want the write token", digest, token, ok, err)
	}

	put(" "+string(canonical), "padded")
	if token, _, _ := store.Signature(digest); token != "signed" {
		t.Fatalf("a non-canonical body replaced the signature with %q", token)
	}

	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); err != nil {
		t.Fatal(err)
	}
	st, err := store.State()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Signature(st.Policy); ok {
		t.Fatal("a per-workload write left its policy signed")
	}
}

func TestConsumeToken(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	until := time.Now().Add(time.Hour)
	if err := store.ConsumeToken("t1", until); err != nil {
		t.Fatalf("first use = %v", err)
	}
	if err := store.ConsumeToken("t1", until); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("reuse = %v, want ErrTokenReused", err)
	}
	if err := store.ConsumeToken("t2", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeToken("t2", until); err != nil {
		t.Fatalf("reuse after the record expired = %v, want it pruned", err)
	}
}
