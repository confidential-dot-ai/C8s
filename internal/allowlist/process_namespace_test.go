package allowlist

import (
	"bytes"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func namespacePolicyDocument(
	t *testing.T,
	shared bool,
) *pkgallowlist.Allowlist {
	t.Helper()
	w := oneContainerWorkload(mustParseDigest(t, digestA))
	w.Containers[0].Command = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/worker"}}
	w.Containers[0].Args.Policy = pkgallowlist.PolicyDeny
	w.Containers[0].Mounts.Policy = pkgallowlist.PolicyDeny
	w.Containers[0].Env.Policy = pkgallowlist.PolicyDeny
	w.Containers[0].ShareProcessNamespace = shared
	al := &pkgallowlist.Allowlist{Schema: pkgallowlist.ProcessNamespaceSchema, Workloads: map[string]pkgallowlist.Workload{"pair": w}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	return al
}

func TestProcessNamespaceSchemaPreservesSignedDocumentsAndSnapshots(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-v2-private", true: "shared"}[shared], func(t *testing.T) {
			store, handle := openJournaledStore(t)
			doc := namespacePolicyDocument(t, shared)
			canonical, err := doc.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			const token = "operator-namespace-policy-token"
			if err := handle.ReplaceAll(doc, OperatorWrite{Signature: token}); err != nil {
				t.Fatal(err)
			}
			check := func(handle *Handle) {
				t.Helper()
				loaded, _, err := handle.LoadAll()
				if err != nil || loaded.Schema != pkgallowlist.ProcessNamespaceSchema {
					t.Fatalf("LoadAll = %+v, %v", loaded, err)
				}
				body, err := loaded.Canonical()
				if err != nil || !bytes.Equal(body, canonical) {
					t.Fatalf("served signed document changed: %s, %v", body, err)
				}
				parsed, err := pkgallowlist.ParseServedJSON(body)
				if err != nil || parsed.Workloads["pair"].Containers[0].ShareProcessNamespace != shared {
					t.Fatalf("served namespace policy changed: %v", err)
				}
				digest := objectDigest(canonical)
				if got, ok, err := handle.Signature(digest); err != nil || !ok || got != token {
					t.Fatalf("Signature = %q, %v, %v", got, ok, err)
				}
				if body, ok, err := handle.Object(digest); err != nil || !ok || !bytes.Equal(body, canonical) {
					t.Fatalf("journal object changed: %s, %v, %v", body, ok, err)
				}
			}
			check(handle)
			image, err := store.Dump()
			if err != nil {
				t.Fatal(err)
			}
			fresh, restored := openInMemoryStore(t)
			if err := fresh.Restore(image, store.Digest()); err != nil {
				t.Fatal(err)
			}
			check(restored)
		})
	}
}

func TestProcessNamespaceSchemaUpgradesAnOldSnapshotInALoggedWrite(t *testing.T) {
	old, handle := openJournaledStore(t)
	putEntry(t, handle, "private", oneContainerWorkload(mustParseDigest(t, digestB)))
	var tables int
	if err := old.db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'allowlist_document'").Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("v1 database unexpectedly has schema metadata: %d, %v", tables, err)
	}
	image, err := old.Dump()
	if err != nil {
		t.Fatal(err)
	}
	fresh, restored := openInMemoryStore(t)
	if err := fresh.Restore(image, old.Digest()); err != nil {
		t.Fatal(err)
	}
	if fresh.Digest() != old.Digest() {
		t.Fatal("restoring an old snapshot changed its content digest")
	}
	loaded, _, err := restored.LoadAll()
	if err != nil || loaded.Schema != pkgallowlist.Schema {
		t.Fatalf("old document schema changed: %+v, %v", loaded, err)
	}
	shared := namespacePolicyDocument(t, true)
	if err := restored.ReplaceAll(shared, OperatorWrite{}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = restored.LoadAll()
	if err != nil || loaded.Schema != pkgallowlist.ProcessNamespaceSchema {
		t.Fatalf("shared document was not upgraded: %+v, %v", loaded, err)
	}
}

func TestProcessNamespaceSeedUsesTheRequiredSchema(t *testing.T) {
	_, handle := openJournaledStore(t)
	doc := namespacePolicyDocument(t, true)
	if _, _, err := handle.SeedWorkloads(doc.Workloads); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := handle.LoadAll()
	if err != nil || loaded.Schema != pkgallowlist.ProcessNamespaceSchema {
		t.Fatalf("seed namespace schema = %+v, %v", loaded, err)
	}
}
