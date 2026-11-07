package allowlist

import (
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
	store := openJournaled(t)
	seeded := hostBindWorkload(mustParseDigest(t, digestA), "/var/lib/seeded")
	own := hostBindWorkload(mustParseDigest(t, digestB), "/var/lib/own")
	plain := oneContainerWorkload(mustParseDigest(t, digestC))
	write := func(workloads map[string]pkgallowlist.Workload) {
		t.Helper()
		if err := store.ReplaceAll(&pkgallowlist.Allowlist{
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

	if _, _, err := store.SeedWorkloads(map[string]pkgallowlist.Workload{"seeded": seeded}); err != nil {
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
	store := openJournaled(t)
	served, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"bound":{"containers":[` +
		`{"digest":"` + digestA + `","command":{"policy":"deny"},"args":{"policy":"deny"},"env":{"policy":"any"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/node","kind":"host","source":"/var/lib/seeded"}]}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	spelled := served.Workloads["bound"]
	spelled.InitContainers = []pkgallowlist.Container{}
	if _, _, err := store.SeedWorkloads(map[string]pkgallowlist.Workload{"bound": spelled}); err != nil {
		t.Fatal(err)
	}
	if got := hostPrivilege(t, store); !got.DeclaredBySeed {
		t.Fatalf("seeding a host bind records %+v", got)
	}

	if err := store.ReplaceAll(served, OperatorWrite{}); err != nil {
		t.Fatal(err)
	}
	if got := hostPrivilege(t, store).FirstOperatorGrant; got != nil {
		t.Errorf("the write serving the seeded declaration granted %+v", got)
	}
}

// An operator write declares no seed, whatever host privilege it grants.
func TestTheSeedFieldReportsTheSeedAlone(t *testing.T) {
	store := openJournaled(t)
	putEntry(t, store, "own", hostBindWorkload(mustParseDigest(t, digestA), "/var/lib/own"))
	if got := hostPrivilege(t, store); got.DeclaredBySeed || got.FirstOperatorGrant == nil {
		t.Fatalf("after an operator write granting host privilege the store records %+v", got)
	}
}
