package allowlist

import (
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestProcessNamespaceApplySelectsAndRetainsTheRequiredSchema(t *testing.T) {
	entry := `{"pair":{"containers":[{"digest":"` + testDigest + `","command":{"policy":"exact","argv":["/worker"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"shareProcessNamespace":true}]}}`
	entries, err := parseWorkloadEntries([]byte(entry))
	if err != nil {
		t.Fatal(err)
	}
	read := allowlistRead{document: &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{}}}
	document := documentWith(read, entries)
	if document.Schema != pkgallowlist.ProcessNamespaceSchema {
		t.Fatalf("applying a shared entry kept schema %q", document.Schema)
	}
	canonical, err := document.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkgallowlist.ParseJSON(canonical); err != nil {
		t.Fatalf("apply produced an invalid policy: %v", err)
	}
	read.document = document
	without := documentWithout(read, []string{"pair"})
	if without.Schema != pkgallowlist.ProcessNamespaceSchema {
		t.Fatal("deleting an entry silently changed the existing document schema")
	}
}
