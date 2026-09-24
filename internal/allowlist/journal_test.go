package allowlist

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestJournalBound(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth"); err != nil {
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
