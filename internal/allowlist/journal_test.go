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
	if err := store.StartJournal("sha256:auth", 0, 0); err != nil {
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
	if err := store.StartJournal("sha256:auth", 10*time.Second, 0); err != nil {
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
	if err := store.StartJournal("sha256:auth", time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}

	if err := store.StartJournal("sha256:auth", 0, 0); err != nil {
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

// A narrowing widens the bound; once the named-leaf TTL has run from its
// activation, Drain appends a drained event and the bound collapses.
func TestJournalDrainCollapsesBoundAfterActivation(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 10*time.Second, time.Hour); err != nil {
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
	if len(widened.Bound) != 2 || widened.Pending == "" {
		t.Fatalf("state after a narrowing = %+v, want a 2-entry bound and a pending target", widened)
	}
	if ok, err := store.Drain(time.Now().Add(24 * time.Hour)); ok || err != nil {
		t.Fatalf("Drain while the narrowing is pending = %v, %v; want false", ok, err)
	}
	// Far from StartJournal, so the drain clock must start at activation, not
	// at process start.
	activated := time.Now().Add(2 * time.Hour)
	if ok, err := store.Activate(activated); !ok || err != nil {
		t.Fatalf("activate narrowing = %v, %v", ok, err)
	}
	if ok, err := store.Drain(activated.Add(59 * time.Minute)); ok || err != nil {
		t.Fatalf("Drain before the leaf TTL ran = %v, %v; want false", ok, err)
	}
	if ok, err := store.Drain(activated.Add(time.Hour + time.Second)); !ok || err != nil {
		t.Fatalf("Drain after the leaf TTL = %v, %v; want true", ok, err)
	}
	st, err := store.State()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(st.Bound, []string{widened.Policy}) || st.Policy != widened.Policy || st.Position != widened.Position+1 {
		t.Fatalf("drained state = %+v, want bound [%s] at position %d", st, widened.Policy, widened.Position+1)
	}
	ev := headEvent(t, &store, st)
	if ev.Type != EventDrained || ev.Parent != widened.Head || ev.Target != widened.Policy || ev.Authority != "sha256:auth" {
		t.Fatalf("drained event = %+v, want a drained event on %s chained to %s", ev, widened.Policy, widened.Head)
	}
	if ok, err := store.Drain(activated.Add(2 * time.Hour)); ok || err != nil {
		t.Fatalf("second Drain = %v, %v; want false (already drained)", ok, err)
	}

	// The next narrowing widens the drained bound again.
	if err := store.PutWorkload("b", oneContainerWorkload(mustParseDigest(t, digestB))); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Activate(activated.Add(3 * time.Hour)); !ok || err != nil {
		t.Fatalf("activate = %v, %v", ok, err)
	}
	if _, err := store.DeleteWorkload("b"); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.State(); len(st.Bound) != 2 {
		t.Fatalf("bound after a narrowing over a drained bound = %v, want 2 entries", st.Bound)
	}
}

func TestJournalDrainWithoutLease(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteWorkload("a"); err != nil {
		t.Fatal(err)
	}
	published := time.Now()
	if st, _ := store.State(); len(st.Bound) != 2 {
		t.Fatalf("bound after a narrowing = %v, want 2 entries", st.Bound)
	}
	if ok, err := store.Drain(published.Add(59 * time.Minute)); ok || err != nil {
		t.Fatalf("early Drain = %v, %v; want false", ok, err)
	}
	if ok, err := store.Drain(published.Add(time.Hour + time.Minute)); !ok || err != nil {
		t.Fatalf("Drain = %v, %v; want true", ok, err)
	}
	if st, _ := store.State(); len(st.Bound) != 1 {
		t.Fatalf("drained bound = %v, want 1 entry", st.Bound)
	}
}

func TestJournalDrainDisabled(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteWorkload("a"); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Drain(time.Now().Add(1000 * time.Hour)); ok || err != nil {
		t.Fatalf("Drain with drainAfter 0 = %v, %v; want false", ok, err)
	}
}

// narrowed starts a journal at t0 (lease 0, drainAfter 1h) and leaves the
// bound widened by a removal published at pub.
func narrowed(t *testing.T, store *Store, t0, pub time.Time) {
	t.Helper()
	store.now = func() time.Time { return t0 }
	if err := store.StartJournal("sha256:auth", 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return pub }
	if _, err := store.DeleteWorkload("a"); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.State(); len(st.Bound) != 2 {
		t.Fatalf("bound after a narrowing = %v, want 2 entries", st.Bound)
	}
}

// Without a lease the drain clock starts at the publication, and a restart
// starts it again.
func TestJournalDrainClock(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	t0 := time.Now()
	pub := t0.Add(2 * time.Hour)
	narrowed(t, &store, t0, pub)
	if ok, err := store.Drain(pub.Add(59 * time.Minute)); ok || err != nil {
		t.Fatalf("Drain 59m after a lease-0 publication = %v, %v; want false", ok, err)
	}

	restart := t0.Add(3 * time.Hour)
	store.now = func() time.Time { return restart }
	if err := store.StartJournal("sha256:auth", 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Drain(restart.Add(59 * time.Minute)); ok || err != nil {
		t.Fatalf("Drain 59m after a restart = %v, %v; want false", ok, err)
	}
	if ok, err := store.Drain(restart.Add(time.Hour + time.Second)); !ok || err != nil {
		t.Fatalf("Drain after drainAfter from the restart = %v, %v; want true", ok, err)
	}
}

// A journal written before journal_served existed starts its drain clock at
// StartJournal.
func TestJournalDrainLegacyJournal(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	t0 := time.Now()
	narrowed(t, &store, t0, t0)
	if _, err := store.db.Exec("DELETE FROM journal_served"); err != nil {
		t.Fatal(err)
	}
	if err := store.StartJournal("sha256:auth", 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Drain(t0.Add(time.Hour + time.Second)); !ok || err != nil {
		t.Fatalf("Drain on a legacy journal = %v, %v; want true", ok, err)
	}
}
