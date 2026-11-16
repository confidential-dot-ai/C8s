package allowlist

import (
	"errors"
	"reflect"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// hostBindWorkload declares host privilege: one container binding a host path.
func hostBindWorkload(digest types.Digest, source string) pkgallowlist.Workload {
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{
		Digest: digest,
		Mounts: pkgallowlist.MountPolicy{
			Policy: pkgallowlist.PolicyExact,
			Rules: []pkgallowlist.MountRule{{
				Destination: "/node",
				Kind:        pkgallowlist.MountHost,
				Source:      source,
			}},
		},
	}}}
}

func hostPrivilege(t *testing.T, store *Store) HostPrivilege {
	t.Helper()
	history, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	return history.HostPrivilege
}

// Seeding reports the seed's own host privilege and grants none. The record then
// names the first operator write serving a declaration the store did not hold.
func TestTheRecordNamesTheWriteThatGrantedHostPrivilege(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	seeded := hostBindWorkload(mustParseDigest(t, digestA), "/var/lib/seeded")
	own := hostBindWorkload(mustParseDigest(t, digestB), "/var/lib/own")
	plain := oneContainerWorkload(mustParseDigest(t, digestC))
	write := func(workloads map[string]pkgallowlist.Workload) {
		t.Helper()
		if err := allowlist.ReplaceAll(&pkgallowlist.Allowlist{
			Schema:    pkgallowlist.Schema,
			Workloads: workloads,
		}, OperatorWrite{}); err != nil {
			t.Fatal(err)
		}
	}
	record := func(step string, want HostPrivilege) {
		t.Helper()
		if got := hostPrivilege(t, store); !reflect.DeepEqual(got, want) {
			t.Fatalf("after %s the store records %+v, want %+v", step, got, want)
		}
	}

	record("opening the store", HostPrivilege{})

	if _, _, err := allowlist.SeedWorkloads(map[string]pkgallowlist.Workload{"seeded": seeded}); err != nil {
		t.Fatal(err)
	}
	record("seeding a declaration", HostPrivilege{DeclaredBySeed: true})

	write(map[string]pkgallowlist.Workload{"seeded": seeded, "plain": plain})
	record("a write serving the seeded declaration", HostPrivilege{DeclaredBySeed: true})

	write(map[string]pkgallowlist.Workload{"moved": seeded})
	record("a write moving it under another name", HostPrivilege{DeclaredBySeed: true})

	write(map[string]pkgallowlist.Workload{"moved": seeded, "own": own})
	history := mustHistory(t, store)
	granted := HostPrivilege{
		DeclaredBySeed:     true,
		FirstOperatorGrant: &HostPrivilegeGrant{Digest: history[len(history)-1].Digest},
	}
	record("a write serving a declaration of its own", granted)

	write(map[string]pkgallowlist.Workload{"plain": plain})
	record("a write taking every declaration away", granted)

	write(map[string]pkgallowlist.Workload{"plain": plain, "own": own})
	record("a write serving the declaration again", granted)
}

// Both sides are compared as declarations, not as the bytes a document spelled.
func TestAWriteServingTheSeededDeclarationGrantsNothing(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	served, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"bound":{"containers":[` +
		`{"digest":"` + digestA + `","command":{"policy":"deny"},"args":{"policy":"deny"},"env":{"policy":"any"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/node","kind":"host","source":"/var/lib/seeded"}]}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	spelled := served.Workloads["bound"]
	spelled.InitContainers = []pkgallowlist.Container{}
	if _, _, err := allowlist.SeedWorkloads(map[string]pkgallowlist.Workload{"bound": spelled}); err != nil {
		t.Fatal(err)
	}
	if got := hostPrivilege(t, store); !got.DeclaredBySeed {
		t.Fatalf("seeding a host bind records %+v", got)
	}

	if err := allowlist.ReplaceAll(served, OperatorWrite{}); err != nil {
		t.Fatal(err)
	}
	if got := hostPrivilege(t, store).FirstOperatorGrant; got != nil {
		t.Errorf("the write serving the seeded declaration granted %+v", got)
	}
}

// An operator write declares no seed, whatever host privilege it grants.
func TestTheSeedFieldReportsTheSeedAlone(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	putEntry(t, allowlist, "own", hostBindWorkload(mustParseDigest(t, digestA), "/var/lib/own"))
	if got := hostPrivilege(t, store); got.DeclaredBySeed || got.FirstOperatorGrant == nil {
		t.Fatalf("after an operator write granting host privilege the store records %+v", got)
	}
}

// The record outlives pruning and travels in a snapshot; an emptied store holds none.
func TestTheHostPrivilegeRecordLastsAsLongAsTheStore(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	if _, _, err := allowlist.SeedWorkloads(map[string]pkgallowlist.Workload{
		"seeded": hostBindWorkload(mustParseDigest(t, digestA), "/var/lib/seeded"),
	}); err != nil {
		t.Fatal(err)
	}
	putEntry(t, allowlist, "own", hostBindWorkload(mustParseDigest(t, digestB), "/var/lib/own"))
	for i := range 3 {
		putEntry(t, allowlist, "plain", historyWorkload(t, i))
	}
	want := hostPrivilege(t, store)
	if !want.DeclaredBySeed || want.FirstOperatorGrant == nil {
		t.Fatalf("the store records %+v, want the seed and the granting write", want)
	}

	if err := store.pruneHistory(1); err != nil {
		t.Fatal(err)
	}
	if got := hostPrivilege(t, store); !reflect.DeepEqual(got, want) {
		t.Errorf("pruning the history left %+v, want %+v", got, want)
	}
	image, err := store.Dump()
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := openInMemoryStore(t)
	if got := hostPrivilege(t, fresh); got.DeclaredBySeed || got.FirstOperatorGrant != nil {
		t.Errorf("a fresh store records %+v", got)
	}
	if err := fresh.Restore(image, store.Digest()); err != nil {
		t.Fatal(err)
	}
	if got := hostPrivilege(t, fresh); !reflect.DeepEqual(got, want) {
		t.Errorf("a restored snapshot records %+v, want %+v", got, want)
	}
	if err := fresh.Empty(); err != nil {
		t.Fatal(err)
	}
	if got := hostPrivilege(t, fresh); got.DeclaredBySeed || got.FirstOperatorGrant != nil {
		t.Errorf("an emptied store records %+v", got)
	}
}

// A database image without the record is refused and leaves the store as it was.
func TestRestoreRefusesAnImageWithoutTheHostPrivilegeRecord(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	putEntry(t, allowlist, "own", hostBindWorkload(mustParseDigest(t, digestA), "/var/lib/own"))
	if _, err := store.db.Exec("DROP TABLE host_privilege"); err != nil {
		t.Fatal(err)
	}
	image, err := store.Dump()
	if err != nil {
		t.Fatal(err)
	}
	content, _, err := store.ScanDigest()
	if err != nil {
		t.Fatal(err)
	}

	fresh, _ := openInMemoryStore(t)
	before := hostPrivilege(t, fresh)
	if err := fresh.Restore(image, content); !errors.Is(err, errNoHostPrivilegeRecord) {
		t.Fatalf("Restore = %v, want it refused", err)
	}
	if got := hostPrivilege(t, fresh); !reflect.DeepEqual(got, before) {
		t.Errorf("the refused restore left %+v, want %+v", got, before)
	}
}
