package cmdsutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// A credential client follows the policy the enforcer rewrites in place; a
// half-written document leaves its set as it was.
func TestNodePinsFollowsTheMountedPolicy(t *testing.T) {
	src, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := refvalues.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cds-pins.json")
	if n, err := FollowNodePins(path); n != nil || err != nil {
		t.Fatalf("absent policy: %v %v", n, err)
	}
	if _, err := NewNodePins(path); err == nil {
		t.Fatal("absent policy accepted")
	}
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FollowNodePins(filepath.Join(path, "x")); err == nil {
		t.Fatal("a stat error other than absent ignored")
	}
	n, err := FollowNodePins(path)
	if err != nil || n.Generation() != 1 || len(n.Current().Images) != len(set.Images) {
		t.Fatalf("start: %v", err)
	}
	if changed, err := n.Refresh(t.Context()); changed || err != nil {
		t.Fatalf("unchanged file: %v %v", changed, err)
	}
	if err := os.WriteFile(path, src[:len(src)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := n.Refresh(t.Context()); changed || err == nil || n.Generation() != 1 {
		t.Fatalf("half-written: %v %v", changed, err)
	}
	fewer := set
	fewer.Images = set.Images[:1]
	doc, err := refvalues.Format(fewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := n.Refresh(t.Context()); !changed || err != nil || n.Generation() != 2 || len(n.Current().Images) != 1 {
		t.Fatalf("rewritten: %v %v", changed, err)
	}
}
