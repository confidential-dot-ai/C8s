package allowlist

import (
	"bytes"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestDiffAllowlistsWorkloads(t *testing.T) {
	mk := func(argv string) pkgallowlist.Container {
		return pkgallowlist.Container{
			Digest:  mustDigest(t, digB),
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{argv}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		}
	}
	live := &pkgallowlist.Allowlist{
		Schema: pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{
			"web":  {Containers: []pkgallowlist.Container{mk("/old")}},
			"gone": {Containers: []pkgallowlist.Container{{Digest: mustDigest(t, digC)}}},
		},
	}
	desired := &pkgallowlist.Allowlist{
		Schema: pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{
			"web": {Containers: []pkgallowlist.Container{mk("/new")}},
			"new": {Containers: []pkgallowlist.Container{{Digest: mustDigest(t, digD)}}},
		},
	}

	d := diffAllowlists(live, desired)
	if d.empty() {
		t.Fatal("expected differences")
	}
	if len(d.WorkloadsAdded) != 1 || d.WorkloadsAdded[0] != "new" {
		t.Fatalf("workloadsAdded = %#v", d.WorkloadsAdded)
	}
	if len(d.WorkloadsRemoved) != 1 || d.WorkloadsRemoved[0] != "gone" {
		t.Fatalf("workloadsRemoved = %#v", d.WorkloadsRemoved)
	}
	web, ok := d.WorkloadsChanged["web"]
	if !ok || len(web.Changed) != 1 {
		t.Fatalf("web changed = %#v", web)
	}
	if web.Changed[0].Digest != digB || web.Changed[0].From == web.Changed[0].To {
		t.Fatalf("web container change = %#v", web.Changed[0])
	}
}

func TestMultisetSubRespectsMultiplicity(t *testing.T) {
	got := multisetSub([]string{"x", "x", "y"}, []string{"x"})
	if len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Fatalf("multisetSub = %v, want [x y]", got)
	}
	if got := multisetSub([]string{"x", "x"}, []string{"x", "x"}); len(got) != 0 {
		t.Fatalf("full overlap must subtract to empty, got %v", got)
	}
}

func TestPrintDiffTextWorkloadChange(t *testing.T) {
	mk := func(argv string) pkgallowlist.Container {
		return pkgallowlist.Container{
			Digest:  mustDigest(t, digB),
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{argv}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		}
	}
	base := func(ctr pkgallowlist.Container) *pkgallowlist.Allowlist {
		return &pkgallowlist.Allowlist{
			Schema:    pkgallowlist.Schema,
			Workloads: map[string]pkgallowlist.Workload{"web": {Containers: []pkgallowlist.Container{ctr}}},
		}
	}

	var buf bytes.Buffer
	if err := printDiff(&buf, "text", diffAllowlists(base(mk("/old")), base(mk("/new")))); err != nil {
		t.Fatalf("printDiff: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "workloads:\n~ web\n") {
		t.Fatalf("printDiff output:\n%s", out)
	}
	if !strings.Contains(out, "~ main "+digB) {
		t.Fatalf("missing container change line:\n%s", out)
	}
}

func TestPrintDiffOrdersMapEntries(t *testing.T) {
	d := allowlistDiff{
		WorkloadsChanged: map[string]entryDiff{
			"z": {Label: &changedEntry{From: "old", To: "Z"}},
			"y": {Label: &changedEntry{From: "old", To: "Y"}},
		},
	}
	want := "workloads:\n~ y\n    label: \"old\" -> \"Y\"\n~ z\n    label: \"old\" -> \"Z\"\n"
	for range 20 {
		var out bytes.Buffer
		if err := printDiff(&out, "text", d); err != nil {
			t.Fatal(err)
		}
		if out.String() != want {
			t.Fatalf("diff output = %q, want %q", out.String(), want)
		}
	}
}

func TestDiffEntrySecrets(t *testing.T) {
	grant := func(read ...string) *pkgallowlist.SecretsPolicy {
		return &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: read}
	}
	tests := []struct {
		name     string
		live     *pkgallowlist.SecretsPolicy
		desired  *pkgallowlist.SecretsPolicy
		wantFrom string
		wantTo   string
	}{
		{name: "both deny", live: nil, desired: nil},
		{name: "same grant", live: grant("db/*"), desired: grant("db/*")},
		{name: "grant added", live: nil, desired: grant("db/*"), wantFrom: "deny", wantTo: `allow read=["db/*"]`},
		{name: "grant removed", live: grant("db/*"), desired: nil, wantFrom: `allow read=["db/*"]`, wantTo: "deny"},
		{name: "read widened", live: grant("db/a"), desired: grant("db/a", "db/b"), wantFrom: `allow read=["db/a"]`, wantTo: `allow read=["db/a" "db/b"]`},
		{name: "comma inside a path", live: grant("db/a,db/b"), desired: grant("db/a", "db/b"), wantFrom: `allow read=["db/a,db/b"]`, wantTo: `allow read=["db/a" "db/b"]`},
		{
			name:     "write added",
			live:     grant("db/a"),
			desired:  &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"db/a"}, Write: []string{"db/a"}},
			wantFrom: `allow read=["db/a"]`,
			wantTo:   `allow read=["db/a"] write=["db/a"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := pkgallowlist.Container{Digest: mustDigest(t, digB)}
			ed := diffEntry(
				pkgallowlist.Workload{Containers: []pkgallowlist.Container{c}, Secrets: tt.live},
				pkgallowlist.Workload{Containers: []pkgallowlist.Container{c}, Secrets: tt.desired},
			)
			if tt.wantTo == "" {
				if !ed.empty() {
					t.Fatalf("diffEntry = %+v, want empty", ed)
				}
				return
			}
			if ed.empty() || ed.Secrets == nil {
				t.Fatalf("diffEntry = %+v, want a secrets change", ed)
			}
			if ed.Secrets.From != tt.wantFrom || ed.Secrets.To != tt.wantTo {
				t.Errorf("secrets = %q -> %q, want %q -> %q", ed.Secrets.From, ed.Secrets.To, tt.wantFrom, tt.wantTo)
			}
		})
	}
}
