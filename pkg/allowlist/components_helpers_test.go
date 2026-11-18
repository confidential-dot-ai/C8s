package allowlist

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

var deadline = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

// retiringSet is the set componentEntry declares, retiring at deadline.
func retiringSet(version, name, digest string) string {
	return `"` + version + `":{"retire":{"deadline":"2026-12-01T00:00:00Z"},"entries":{"` + name + `":` +
		componentEntry(digest, RoleMesh) + `}}`
}

// meshLaunch is the launch componentEntry admits.
func meshLaunch(digest string) RunningContainer {
	return RunningContainer{
		Digest: digest,
		Argv:   []string{"/app/c8s", "armtls-mesh", "--pod"},
		Mounts: []ObservedMount{{
			Destination: "/run/c8s",
			Class:       MountEmptyDir,
			Storage:     MountMemory,
			Volume:      "c8s-run",
		}},
	}
}

func TestComponentSetDigestNamesTheBytes(t *testing.T) {
	al := mustParse(t, componentsDoc(currentSet(), retiringSet("0.42.1", "c8s-mesh-endpoint", digestB)))
	current, err := al.Components[currentSetVersion].Digest()
	if err != nil {
		t.Fatal(err)
	}
	retiring, err := al.Components["0.42.1"].Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, retiring) {
		t.Fatal("two sets share one digest")
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	reread, err := again.Components[currentSetVersion].Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, reread) {
		t.Fatal("a set's digest changed across a round trip")
	}
	retired := al.Components[currentSetVersion]
	retired.Retire = &Retirement{Deadline: Deadline{deadline}}
	afterRetire, err := retired.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, afterRetire) {
		t.Fatal("retiring a set changed its digest")
	}
}

// A deadline ends the set at the instant it names, not after it.
func TestComponentSetInForce(t *testing.T) {
	al := mustParse(t, componentsDoc(currentSet(), retiringSet("0.42.1", "c8s-mesh-endpoint", digestB)))
	current := al.Components[currentSetVersion]
	retiring := al.Components["0.42.1"]
	for _, tc := range []struct {
		name    string
		set     ComponentSet
		now     time.Time
		inForce bool
	}{
		{"current before the deadline", current, deadline.Add(-time.Second), true},
		{"current after the deadline", current, deadline.Add(time.Hour), true},
		{"retiring before the deadline", retiring, deadline.Add(-time.Second), true},
		{"retiring at the deadline", retiring, deadline, false},
		{"retiring after the deadline", retiring, deadline.Add(time.Second), false},
	} {
		if got := tc.set.InForce(tc.now); got != tc.inForce {
			t.Errorf("%s: InForce = %v, want %v", tc.name, got, tc.inForce)
		}
	}
	if !current.Current() || retiring.Current() {
		t.Error("Current does not report the set without a retirement")
	}
}

// Sets come out in version order, which is not the order of their keys.
func TestSetsInForceAreOrderedByVersion(t *testing.T) {
	al := mustParse(t, componentsDoc(
		`"0.10.0":{"entries":{}}`,
		`"0.9.0":{"entries":{}}`,
		retiringSet("0.8.1", "c8s-mesh-endpoint", digestB),
	))
	refs := al.SetsInForce(deadline.Add(-time.Hour))
	versions := []string{}
	for _, ref := range refs {
		versions = append(versions, ref.Version)
		if digest := al.Components[ref.Version].DigestString(); ref.Digest != digest {
			t.Errorf("set %s names digest %s, want %s", ref.Version, ref.Digest, digest)
		}
	}
	if want := []string{"0.8.1", "0.9.0", "0.10.0"}; !equalStrings(versions, want) {
		t.Fatalf("SetsInForce = %v, want %v", versions, want)
	}
	past := al.SetsInForce(deadline)
	if len(past) != 2 {
		t.Fatalf("SetsInForce past the deadline = %v, want the two current sets", past)
	}
}

// A container two releases carry is on both their sets, and on neither once
// their deadline has passed.
func TestSetsAdmitting(t *testing.T) {
	al := mustParse(t, componentsDoc(
		retiringSet("0.42.1", "c8s-mesh-endpoint", digestA),
		`"0.43.0":{"entries":{"c8s-mesh-endpoint":`+componentEntry(digestA, RoleMesh)+`}}`,
	))
	launch := meshLaunch(digestA)
	before := al.SetsAdmitting(launch, deadline.Add(-time.Hour))
	if len(before) != 2 || before[0].Version != "0.42.1" || before[1].Version != "0.43.0" {
		t.Fatalf("SetsAdmitting = %v, want both sets", before)
	}
	after := al.SetsAdmitting(launch, deadline)
	if len(after) != 1 || after[0].Version != "0.43.0" {
		t.Fatalf("SetsAdmitting past the deadline = %v, want the current set", after)
	}
	otherArgv := launch
	otherArgv.Argv = []string{"/bin/sh"}
	if got := al.SetsAdmitting(otherArgv, deadline.Add(-time.Hour)); got != nil {
		t.Fatalf("a launch no entry admits is on %v", got)
	}
	if got := al.SetsAdmitting(meshLaunch("not-a-digest"), deadline.Add(-time.Hour)); got != nil {
		t.Fatalf("an unreadable digest is on %v", got)
	}
}

// A component container names the set that declares it after that set has
// ended, so a node can tell it from a container no set ever declared.
func TestSetsDeclaringIgnoresRetirement(t *testing.T) {
	al := mustParse(t, componentsDoc(
		retiringSet("0.42.1", "c8s-mesh-endpoint", digestA),
		`"0.43.0":{"entries":{"c8s-mesh-endpoint":`+componentEntry(digestB, RoleMesh)+`}}`,
	))
	ended := al.SetsDeclaring(meshLaunch(digestA))
	if len(ended) != 1 || ended[0].Version != "0.42.1" {
		t.Fatalf("SetsDeclaring = %v, want the retired set", ended)
	}
	if al.SetsAdmitting(meshLaunch(digestA), deadline) != nil {
		t.Fatal("the retired set admits its entry past the deadline")
	}
	current := al.SetsDeclaring(meshLaunch(digestB))
	if len(current) != 1 || current[0].Version != "0.43.0" {
		t.Fatalf("SetsDeclaring = %v, want the current set", current)
	}
	if got := al.SetsDeclaring(meshLaunch(digestC)); got != nil {
		t.Fatalf("a launch no set declares is declared by %v", got)
	}
	if got := al.SetsDeclaring(meshLaunch("not-a-digest")); got != nil {
		t.Fatalf("an unreadable digest is declared by %v", got)
	}
}

// The index over the sets in force binds their roles, and loses them with the
// set.
func TestBuildIndexAtCoversTheSetsInForce(t *testing.T) {
	al := mustParse(t, componentsDoc(retiringSet("0.42.1", "c8s-mesh-endpoint", digestA)))
	launch := meshLaunch(digestA)
	index := al.BuildIndexAt(deadline.Add(-time.Hour))
	if !index.AdmitsContainer(launch) {
		t.Fatal("the index over a set in force admits none of its containers")
	}
	if got := index.RoleOf(launch); got != RoleMesh {
		t.Fatalf("RoleOf = %q, want %q", got, RoleMesh)
	}
	if !index.BindsRoleMounts(launch, RoleMesh) {
		t.Fatal("a set entry pinning its mounts binds no role mounts")
	}
	retired := al.BuildIndexAt(deadline)
	if retired.AdmitsContainer(launch) || retired.RoleOf(launch) != noRole {
		t.Fatal("a retired set still admits its containers")
	}
	if al.BuildIndex().AdmitsContainer(launch) {
		t.Fatal("the workloads index admits a set's container")
	}
}

// Two releases carrying one entry are one match; two entry names no running
// set can tell apart are ambiguous.
func TestMatchWorkloadAt(t *testing.T) {
	shared := mustParse(t, componentsDoc(
		retiringSet("0.42.1", "c8s-mesh-endpoint", digestA),
		`"0.43.0":{"entries":{"c8s-mesh-endpoint":`+componentEntry(digestA, RoleMesh)+`}}`,
	))
	running := []RunningContainer{meshLaunch(digestA)}
	name, entry, err := shared.MatchWorkloadAt(running, deadline.Add(-time.Hour))
	if err != nil || name != "c8s-mesh-endpoint" || len(entry.Containers) != 1 {
		t.Fatalf("MatchWorkloadAt = %q, %v, %v, want the one entry both sets carry", name, entry, err)
	}
	renamed := mustParse(t, componentsDoc(
		retiringSet("0.42.1", "c8s-mesh-endpoint", digestA),
		`"0.43.0":{"entries":{"c8s-mesh-endpoint-next":`+componentEntry(digestA, RoleMesh)+`}}`,
	))
	if _, _, err := renamed.MatchWorkloadAt(running, deadline.Add(-time.Hour)); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("two entry names matched as one: %v", err)
	}
	name, _, err = renamed.MatchWorkloadAt(running, deadline)
	if err != nil || name != "c8s-mesh-endpoint-next" {
		t.Fatalf("MatchWorkloadAt past the deadline = %q, %v, want the current set's entry", name, err)
	}
	if _, _, err := shared.MatchWorkloadAt(nil, deadline.Add(-time.Hour)); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("an empty running set matched: %v", err)
	}
}

func TestEarliestDeadline(t *testing.T) {
	al := mustParse(t, componentsDoc(
		currentSet(),
		retiringSet("0.42.1", "c8s-mesh-endpoint", digestB),
		`"0.41.0":{"retire":{"deadline":"2026-11-01T00:00:00Z"},"entries":{}}`,
	))
	earlier := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got, retiring := al.EarliestDeadline(earlier.Add(-time.Hour)); !retiring || !got.Equal(earlier) {
		t.Fatalf("EarliestDeadline = %s, %v, want %s", got, retiring, earlier)
	}
	if got, retiring := al.EarliestDeadline(earlier); !retiring || !got.Equal(deadline) {
		t.Fatalf("EarliestDeadline past the first = %s, %v, want %s", got, retiring, deadline)
	}
	if got, retiring := al.EarliestDeadline(deadline); retiring {
		t.Fatalf("EarliestDeadline past every deadline = %s, %v, want none", got, retiring)
	}
	current := mustParse(t, componentsDoc(currentSet()))
	if _, retiring := current.EarliestDeadline(deadline); retiring {
		t.Fatal("a current set named a deadline")
	}
}

// volumedSet is a set whose one entry is the volumed node service, retiring at
// deadline when retiring.
func volumedSet(version, digest string, retiring bool) string {
	retire := ""
	if retiring {
		retire = `"retire":{"deadline":"2026-12-01T00:00:00Z"},`
	}
	return `"` + version + `":{` + retire + `"entries":{"volumed":{"nodeService":true,"containers":[` +
		nodeServiceContainer(digest) + `]}}}`
}

// volumedLaunch is the launch nodeServiceContainer admits.
func volumedLaunch(t *testing.T, digest string) RunningContainer {
	t.Helper()
	env, err := ObserveEnv([]string{"HOME=/root"})
	if err != nil {
		t.Fatal(err)
	}
	return RunningContainer{
		Digest: digest,
		Argv:   []string{"/app/c8s", "volumed", "--state-dir", "/run/c8s"},
		Env:    env,
		Mounts: []ObservedMount{{
			Destination: "/run/c8s",
			Class:       MountEmptyDir,
			Storage:     MountMemory,
		}},
	}
}

// A node service is named by the marked entry of a set in force, under the
// newest set that carries it, and by nothing once that set has ended.
func TestNodeServiceAdmitting(t *testing.T) {
	al := mustParse(t, componentsDoc(currentSet(), volumedSet("0.42.1", digestB, true), volumedSet("0.44.0", digestB, false)))
	launch := volumedLaunch(t, digestB)
	service, named := al.NodeServiceAdmitting(launch, deadline.Add(-time.Hour))
	if !named || service.Entry != "volumed" || service.Set.Version != "0.44.0" {
		t.Fatalf("NodeServiceAdmitting = %+v, %v, want volumed of set 0.44.0", service, named)
	}
	if service.Set.Digest != al.Components["0.44.0"].DigestString() {
		t.Fatalf("the named set digest %s is not the set's", service.Set.Digest)
	}
	if _, named := al.NodeServiceAdmitting(meshLaunch(digestA), deadline.Add(-time.Hour)); named {
		t.Fatal("an entry without the mark named a node service")
	}

	retiring := mustParse(t, componentsDoc(currentSet(), volumedSet("0.42.1", digestB, true)))
	if _, named := retiring.NodeServiceAdmitting(launch, deadline.Add(-time.Hour)); !named {
		t.Fatal("a retiring set named no node service before its deadline")
	}
	if _, named := retiring.NodeServiceAdmitting(launch, deadline); named {
		t.Fatal("a set past its deadline named a node service")
	}
	if !retiring.DeclaresNodeService(deadline.Add(-time.Hour)) || retiring.DeclaresNodeService(deadline) {
		t.Fatal("DeclaresNodeService does not follow the deadline")
	}
}
