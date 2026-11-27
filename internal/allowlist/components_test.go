package allowlist

import (
	"bytes"
	"reflect"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// componentDocument is a written document with a tenant entry and one retiring
// component set.
const componentDocument = `{"schema":"c8s.allowlist/v1","workloads":{"api":{"containers":[` +
	`{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}},` +
	`"components":{"0.43.0":{"retire":{"deadline":"2026-12-01T00:00:00Z"},"entries":{"c8s-mesh-endpoint":{"containers":[` +
	`{"digest":"` + digestB + `","role":"mesh","command":{"policy":"exact","argv":["/app/c8s","armtls-mesh"]},` +
	`"args":{"policy":"any"},"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir","source":"c8s-run"}]}}]}}}}}`

func writeComponentDocument(t *testing.T, allowlist *Handle) *pkgallowlist.Allowlist {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(componentDocument))
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}
	if err := allowlist.ReplaceAll(al, OperatorWrite{}); err != nil {
		t.Fatalf("write document: %v", err)
	}
	return al
}

// A written set is served back whole: the document the Trust Authority judges
// pods against is the document the operator wrote, byte for byte.
func TestStoreCarriesComponentSets(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	allowlist := store.Local()
	if err := allowlist.StartJournal(); err != nil {
		t.Fatal(err)
	}
	written := writeComponentDocument(t, allowlist)

	reloaded, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	set, listed := reloaded.Components["0.43.0"]
	if !listed {
		t.Fatalf("components = %#v, want the written set", reloaded.Components)
	}
	if set.Retire == nil || set.Entries["c8s-mesh-endpoint"].Containers[0].Role != pkgallowlist.RoleMesh {
		t.Fatalf("the stored set lost its retirement or its role: %#v", set)
	}
	wantDigest, err := written.Components["0.43.0"].Digest()
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := set.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantDigest, gotDigest) {
		t.Fatalf("set digest = %x, want %x", gotDigest, wantDigest)
	}

	want, err := written.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	served, _, err := store.Served()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(served, want) {
		t.Fatalf("served document = %s, want %s", served, want)
	}
}

// Seeding is the measured configuration's workloads: it adds entries beside
// the sets an operator wrote and leaves them in place.
func TestSeedWorkloadsKeepsComponentSets(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	allowlist := store.Local()
	if err := allowlist.StartJournal(); err != nil {
		t.Fatal(err)
	}
	writeComponentDocument(t, allowlist)

	added, _, err := allowlist.SeedWorkloads(map[string]pkgallowlist.Workload{
		"seeded": oneContainerWorkload(mustParseDigest(t, digestC)),
	})
	if err != nil || added != 1 {
		t.Fatalf("SeedWorkloads = %d, %v, want one entry added", added, err)
	}
	reloaded, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, listed := reloaded.Components["0.43.0"]; !listed {
		t.Fatalf("seeding dropped the component sets: %#v", reloaded.Components)
	}
	if _, listed := reloaded.Workloads["seeded"]; !listed {
		t.Fatal("seeding did not add its entry")
	}
}

// routerComponentDocument declares a set entry with host ports: the router a
// release publishes is host privilege the operator granted.
const routerComponentDocument = `{"schema":"c8s.allowlist/v1","workloads":{"api":{"containers":[` +
	`{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}},` +
	`"components":{"0.43.0":{"entries":{"c8s-router":{` +
	`"hostPorts":[{"protocol":"TCP","hostPort":443,"containerPort":8443}],"containers":[` +
	`{"digest":"` + digestB + `","role":"router","command":{"policy":"exact","argv":["/app/c8s","router"]},` +
	`"args":{"policy":"deny"},"env":{"policy":"deny"},"mounts":{"policy":"exact","rules":[` +
	`{"destination":"/etc/nginx","kind":"host","source":"/var/lib/c8s/nginx"}]}}]}}}}}`

// The latch covers both sections: a write whose component set introduces a
// declaration is the write that granted it, and a later write serving the same
// set grants nothing.
func TestAComponentSetEntryGrantsHostPrivilege(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	write := func(document string) {
		t.Helper()
		al, err := pkgallowlist.ParseJSON([]byte(document))
		if err != nil {
			t.Fatalf("parse document: %v", err)
		}
		if err := allowlist.ReplaceAll(al, OperatorWrite{}); err != nil {
			t.Fatalf("write document: %v", err)
		}
	}

	write(componentDocument)
	if got := hostPrivilege(t, store).FirstOperatorGrant; got != nil {
		t.Fatalf("a set declaring no host privilege granted %+v", got)
	}

	write(routerComponentDocument)
	history := mustHistory(t, store)
	granted := &HostPrivilegeGrant{Digest: history[len(history)-1].Digest}
	if got := hostPrivilege(t, store).FirstOperatorGrant; !reflect.DeepEqual(got, granted) {
		t.Fatalf("the write adding the router set recorded %+v, want %+v", got, granted)
	}

	write(routerComponentDocument)
	if got := hostPrivilege(t, store).FirstOperatorGrant; !reflect.DeepEqual(got, granted) {
		t.Fatalf("a write serving the same set recorded %+v, want the first grant %+v", got, granted)
	}
}
