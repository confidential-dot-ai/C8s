package allowlist

import (
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Per-user entries share one shape and are told apart by the pod CVM's
// signed assignment. Marked assignedOnly, they lint clean; the same pair
// without the mark, or one marked and one not, stays ambiguous where no
// assignment is involved.
func TestLintAssignedOnlyEntriesShareAShape(t *testing.T) {
	user := func(name string, assigned bool) string {
		mark := ""
		if assigned {
			mark = `"assignedOnly":true,`
		}
		return `"` + name + `":{` + mark + `"containers":[` + ctrJSON(digA, "/opencode") + `],"secrets":{"policy":"allow","read":["/users/` + name + `/**"],"write":["/users/` + name + `/**"]}}`
	}
	ambiguous := func(doc string) bool {
		al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{` + doc + `}}`))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range lintOffline(al) {
			if f.err && (strings.Contains(f.msg, "declare the same containers") || strings.Contains(f.msg, "can never be the unique match")) {
				return true
			}
		}
		return false
	}
	if ambiguous(user("alice", true) + "," + user("bob", true)) {
		t.Fatal("assigned-only per-user entries were reported ambiguous")
	}
	if !ambiguous(user("alice", false) + "," + user("bob", false)) {
		t.Fatal("unassigned duplicate entries were accepted")
	}
	if !ambiguous(user("alice", true) + "," + user("bob", false) + "," + user("carol", false)) {
		t.Fatal("unassigned duplicates beside an assigned entry were accepted")
	}
	if ambiguous(user("alice", true) + "," + user("bob", false)) {
		t.Fatal("one observation-matched entry is not ambiguous")
	}
}
