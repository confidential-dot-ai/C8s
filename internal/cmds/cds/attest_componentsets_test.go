package cds

import (
	"bytes"
	"strings"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// componentDeadline is when the retiring fixture set below ends.
var componentDeadline = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

// docStore serves one parsed document, as the allowlist store does.
type docStore struct {
	al *pkgallowlist.Allowlist
}

func (s docStore) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	return s.al, "1", nil
}

// componentDoc parses a document from the given workloads entries and
// component sets, both JSON object members.
func componentDoc(t *testing.T, workloads, sets []string) docStore {
	t.Helper()
	doc := `{"schema":"` + pkgallowlist.Schema + `","workloads":{` + strings.Join(workloads, ",") +
		`},"components":{` + strings.Join(sets, ",") + `}}`
	al, err := pkgallowlist.ParseJSON([]byte(doc))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return docStore{al: al}
}

func anyArgvEntry(name, digest string) string {
	return `"` + name + `":{"containers":[{"digest":"` + digest +
		`","command":{"policy":"any"},"args":{"policy":"any"}}]}`
}

// componentEntry is a sidecar entry of a set: the launch it pins is
// sidecarLaunch.
func componentEntry(digest, role string) string {
	return `{"containers":[{"digest":"` + digest + `","role":"` + role + `",` +
		`"command":{"policy":"exact","argv":["/app/c8s","armtls-mesh"]},` +
		`"args":{"policy":"any"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir","source":"c8s-run"}]}}]}`
}

func currentSet(version, digest, role string) string {
	return `"` + version + `":{"entries":{"c8s-` + role + `":` + componentEntry(digest, role) + `}}`
}

func retiringSet(version, digest, role string) string {
	return `"` + version + `":{"retire":{"deadline":"2026-12-01T00:00:00Z"},"entries":{"c8s-` + role + `":` +
		componentEntry(digest, role) + `}}`
}

// sidecarLaunch is the container launch componentEntry admits, as the
// inventory reports it.
func sidecarLaunch(digest, role string) workloadclaims.SandboxContainer {
	return workloadclaims.SandboxContainer{
		Digest: digest,
		Role:   role,
		Argv:   []string{"/app/c8s", "armtls-mesh", "--pod"},
		Mounts: []pkgallowlist.ObservedMount{{
			Destination: "/run/c8s",
			Class:       pkgallowlist.MountEmptyDir,
			Storage:     pkgallowlist.MountMemory,
			Volume:      "c8s-run",
		}},
	}
}

// workloadLaunch is the tenant container anyArgvEntry admits.
func workloadLaunch(digest string) workloadclaims.SandboxContainer {
	return workloadclaims.SandboxContainer{Digest: digest, Mounts: []pkgallowlist.ObservedMount{}}
}

func atTime(now time.Time) func(*AttestHandler) {
	return func(h *AttestHandler) { h.Now = func() time.Time { return now } }
}

// A sidecar no workload entry admits passes the membership gate on the set in
// force that declares it, and the pod is still stamped with its own entry.
func TestAttest_ComponentSets_SetInForceAdmitsTheSidecar(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{currentSet("0.43.0", wlDigestB, pkgallowlist.RoleMesh)},
	)
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
	}
	matched := issueWithInventory(t, store, []string{wlDigestA, wlDigestB}, reported, nil)
	if matched == nil || matched.Name != "api" {
		t.Fatalf("matched = %#v, want the tenant entry api", matched)
	}
}

// The deadline alone ends the set: no write happens between the two requests,
// only the clock moves, and the sidecar the set admitted stops being
// allowlisted.
func TestAttest_ComponentSets_DeadlineEndsIssuance(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{retiringSet("0.42.1", wlDigestB, pkgallowlist.RoleMesh)},
	)
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
	}
	digests := []string{wlDigestA, wlDigestB}
	leafFromInventory(t, store, digests, reported, atTime(componentDeadline.Add(-time.Minute)))

	w := attestWithInventory(t, store, digests, reported, atTime(componentDeadline))
	wantWorkloadRefusal(t, w)
}

// A pod whose component containers come from two different sets is on no set,
// and issuance refuses it rather than choosing one.
func TestAttest_ComponentSets_MixingTwoSetsRefused(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{
			currentSet("0.43.0", wlDigestB, pkgallowlist.RoleMesh),
			currentSet("0.44.0", wlDigestC, pkgallowlist.RoleCredentials),
		},
	)
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
		sidecarLaunch(wlDigestC, pkgallowlist.RoleCredentials),
	}
	w := attestWithInventory(t, store, []string{wlDigestA, wlDigestB, wlDigestC}, reported, nil)
	wantWorkloadRefusal(t, w)
}

// An inventory from a worker image whose roles no set declares is judged as
// before: its sidecar is allowlisted by the workloads section and the pod is
// on no set.
func TestAttest_ComponentSets_RolesNoSetAdmitsAreJudgedAsBefore(t *testing.T) {
	store := componentDoc(t,
		[]string{
			anyArgvEntry("api", wlDigestA),
			anyArgvEntry("c8s-mesh-endpoint", wlDigestB),
		},
		[]string{currentSet("0.43.0", wlDigestC, pkgallowlist.RoleMesh)},
	)
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
	}
	matched := issueWithInventory(t, store, []string{wlDigestA, wlDigestB}, reported, nil)
	if matched == nil || matched.Name != "api" {
		t.Fatalf("matched = %#v, want the tenant entry api", matched)
	}
}

// A pod only a retiring set admits gets a leaf that expires with the set, so
// it has to renew before the deadline to keep an identity.
func TestAttest_ComponentSets_LeafExpiresWithTheLastSet(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{retiringSet("0.42.1", wlDigestB, pkgallowlist.RoleMesh)},
	)
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
	}
	leaf := leafFromInventory(t, store, []string{wlDigestA, wlDigestB}, reported,
		atTime(componentDeadline.Add(-30*time.Minute)))
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got > 30*time.Minute || got < 29*time.Minute {
		t.Fatalf("leaf lifetime = %s, want the 30 minutes left of the set", got)
	}
}

// A set that ends between the judgement and the signature refuses the leaf
// rather than signing one that is already expired.
func TestLeafTTL_RefusesAnEndedSet(t *testing.T) {
	h := AttestHandler{Now: func() time.Time { return componentDeadline }}
	if _, err := h.leafTTL(workloadDecision{setsEnd: componentDeadline}); err == nil {
		t.Fatal("a leaf was issued after every set admitting the pod had ended")
	}
}

// A digest is admitted while the set declaring it is in force, and not after.
func TestPolicySnapshot_ContainsCoversTheSetsInForce(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{retiringSet("0.42.1", wlDigestB, pkgallowlist.RoleMesh)},
	)
	snapshot, err := loadPolicySnapshot(store)
	if err != nil {
		t.Fatal(err)
	}
	before, after := componentDeadline.Add(-time.Second), componentDeadline
	for _, tc := range []struct {
		name   string
		digest string
		now    time.Time
		admits bool
	}{
		{"a workload digest, always", wlDigestA, after, true},
		{"the set's digest in force", wlDigestB, before, true},
		{"the set's digest past the deadline", wlDigestB, after, false},
		{"a digest nothing declares", wlDigestC, before, false},
	} {
		digest, err := types.ParseDigest(tc.digest)
		if err != nil {
			t.Fatal(err)
		}
		if got := snapshot.Contains(digest.String(), tc.now); got != tc.admits {
			t.Errorf("%s: Contains = %v, want %v", tc.name, got, tc.admits)
		}
	}
}

// A pod on more than one set is stamped with the newest of them: the release
// its containers have reached, and the one whose entries must keep admitting
// them.
func TestAttest_ComponentSets_LeafNamesTheNewestSet(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{
			currentSet("0.43.0", wlDigestB, pkgallowlist.RoleMesh),
			currentSet("0.44.0", wlDigestB, pkgallowlist.RoleCredentials),
		},
	)
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
	}
	leaf := leafFromInventory(t, store, []string{wlDigestA, wlDigestB}, reported, nil)
	stamp, err := armtls.ComponentSetFromCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if stamp == nil || stamp.Version != "0.44.0" {
		t.Fatalf("stamp = %#v, want the newest set 0.44.0", stamp)
	}
	al, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	want, err := al.Components["0.44.0"].Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stamp.Digest, want) {
		t.Fatalf("stamp digest = %x, want %x", stamp.Digest, want)
	}
}

// A pod on no set carries no stamp, so a verifier can tell a judged pod from
// one the workloads section alone admits.
func TestAttest_ComponentSets_NoSetLeavesTheLeafUnstamped(t *testing.T) {
	store := componentDoc(t,
		[]string{
			anyArgvEntry("api", wlDigestA),
			anyArgvEntry("c8s-mesh-endpoint", wlDigestB),
		},
		[]string{currentSet("0.43.0", wlDigestC, pkgallowlist.RoleMesh)},
	)
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
	}
	leaf := leafFromInventory(t, store, []string{wlDigestA, wlDigestB}, reported, nil)
	stamp, err := armtls.ComponentSetFromCert(leaf)
	if err != nil || stamp != nil {
		t.Fatalf("stamp = %#v, err = %v, want none", stamp, err)
	}
}
