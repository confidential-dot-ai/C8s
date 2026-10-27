package allowlist

import (
	"errors"
	"reflect"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A conditional replace is decided at every replica against the version it
// replaces: a stale one is refused everywhere with its sentinel, and a current
// one lands everywhere.
func TestReplicatedReplaceIfMatch(t *testing.T) {
	st := replicated(t, 3)
	if err := st[0].StartJournal(); err != nil {
		t.Fatal(err)
	}
	if err := st[0].PutWorkload("web", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatal(err)
	}
	version, err := st[1].Version()
	if err != nil {
		t.Fatal(err)
	}
	before := contents(t, st[0])
	doc := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{
		"other": oneContainerWorkload(mustParseDigest(t, digestB)),
	}}

	if err := st[1].ReplaceAllIfMatch(doc, `"1"`); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("stale If-Match: err = %v, want ErrVersionMismatch", err)
	}
	for i, s := range st {
		if !reflect.DeepEqual(contents(t, s), before) {
			t.Fatalf("replica %d changed on a refused precondition", i)
		}
	}

	if err := st[2].ReplaceAllIfMatch(doc, `"`+version+`"`); err != nil {
		t.Fatalf("current If-Match: %v", err)
	}
	want := contents(t, st[0])
	for i, s := range st {
		al, _, err := s.LoadAll()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := al.Workloads["other"]; !ok || len(al.Workloads) != 1 {
			t.Fatalf("replica %d did not take the conditional replace: %v", i, al.Workloads)
		}
		if !reflect.DeepEqual(contents(t, s), want) {
			t.Fatalf("replica %d diverged", i)
		}
	}
}
