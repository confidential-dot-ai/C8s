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

	if err := store.StartJournal("sha256:auth", 0); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); !errors.Is(err, ErrUpdatePending) {
		t.Fatalf("write over a pending update without a lease = %v, want ErrUpdatePending", err)
	}
	if ok, err := store.Activate(time.Now()); !ok || err != nil {
		t.Fatalf("Activate without a lease = %v, %v; want true, nil", ok, err)
	}
	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Workloads["a"]; !ok {
		t.Fatalf("activated document = %v, want the staged entry a", doc.Workloads)
	}
}
