package ta

import (
	"net/http"
	"strings"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
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
	if _, err := h.leafTTL(workloadDecision{admissionEnd: componentDeadline}); err == nil {
		t.Fatal("a leaf was issued after every set admitting the pod had ended")
	}
}

// A digest is admitted while the set declaring it is in force, and not after;
// the admission of one only a retiring set lists ends with that set.
func TestPolicySnapshot_AdmitDigestsCoversTheSetsInForce(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{retiringSet("0.42.1", wlDigestB, pkgallowlist.RoleMesh)},
	)
	snapshot, err := loadPolicySnapshot(store)
	if err != nil {
		t.Fatal(err)
	}
	before := componentDeadline.Add(-time.Second)
	after := componentDeadline
	for _, tc := range []struct {
		name    string
		digests []string
		now     time.Time
		admits  bool
		end     time.Time
	}{
		{name: "a workload digest, always", digests: []string{wlDigestA}, now: after, admits: true},
		{name: "the set's digest in force", digests: []string{wlDigestB}, now: before, admits: true, end: componentDeadline},
		{name: "the set's digest past the deadline", digests: []string{wlDigestB}, now: after},
		{name: "a digest nothing declares", digests: []string{wlDigestC}, now: before},
		{
			name:    "a workload digest beside one only the retiring set lists",
			digests: []string{wlDigestA, wlDigestB},
			now:     before,
			admits:  true,
			end:     componentDeadline,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admitted, err := snapshot.admitDigests(tc.digests, tc.now)
			if (err == nil) != tc.admits {
				t.Fatalf("admitDigests error = %v, want admitted %v", err, tc.admits)
			}
			if err != nil {
				return
			}
			if !admitted.end.Equal(tc.end) {
				t.Errorf("admission ends %v, want %v", admitted.end, tc.end)
			}
		})
	}
}

// The deadline cap follows the admission the gate relied on, not the roles: a
// workload container only a retiring set lists ends the leaf with that set.
func TestAttest_ComponentSets_RolelessDigestFromARetiringSetCapsTheLeaf(t *testing.T) {
	store := componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{
			currentSet("0.43.0", wlDigestC, pkgallowlist.RoleMesh),
			retiringSet("0.42.1", wlDigestB, pkgallowlist.RoleMesh),
		},
	)
	// The sidecar is on the current set; the extra tenant image is listed by
	// the retiring set alone, which no role container names.
	reported := []workloadclaims.SandboxContainer{
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestC, pkgallowlist.RoleMesh),
		sidecarLaunch(wlDigestB, ""),
	}
	digests := []string{wlDigestA, wlDigestB, wlDigestC}
	leaf := leafFromInventory(t, store, digests, reported, atTime(componentDeadline.Add(-30*time.Minute)))
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got > 30*time.Minute || got < 29*time.Minute {
		t.Fatalf("leaf lifetime = %s, want the 30 minutes left of the set listing the image", got)
	}
}

// A Pod CVM is judged by the sets in force as a node sandbox is: its claims
// carry the roles its measured base bound, so mixing two sets refuses the leaf
// and a set's deadline bounds it.
func TestPodAttest_ComponentSets_MixingTwoSetsRefused(t *testing.T) {
	p := podClaimsWith(t,
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
		sidecarLaunch(wlDigestC, pkgallowlist.RoleCredentials),
	)
	h, _ := podTestHandler(t, p)
	h.AllowlistStore = componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{
			currentSet("0.43.0", wlDigestB, pkgallowlist.RoleMesh),
			currentSet("0.44.0", wlDigestC, pkgallowlist.RoleCredentials),
		},
	)
	if w := postPodRequest(t, h, podRequest(t, h, p)); w.Code == http.StatusOK {
		t.Fatal("a Pod CVM mixing two component sets was issued a leaf")
	}
}

func TestPodAttest_ComponentSets_LeafExpiresWithTheLastSet(t *testing.T) {
	p := podClaimsWith(t,
		workloadLaunch(wlDigestA),
		sidecarLaunch(wlDigestB, pkgallowlist.RoleMesh),
	)
	h, _ := podTestHandler(t, p)
	h.AllowlistStore = componentDoc(t,
		[]string{anyArgvEntry("api", wlDigestA)},
		[]string{retiringSet("0.42.1", wlDigestB, pkgallowlist.RoleMesh)},
	)
	atTime(componentDeadline.Add(-30 * time.Minute))(&h)

	w := postPodRequest(t, h, podRequest(t, h, p))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	leaf := leafFromAttestResponse(t, w)
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got > 30*time.Minute || got < 29*time.Minute {
		t.Fatalf("leaf lifetime = %s, want the 30 minutes left of the set", got)
	}
}

// podClaimsWith builds Pod CVM claims whose measurement journal is the given
// containers' digests, in order. A container reported without an argv or
// environment gets the ones claims validation requires.
func podClaimsWith(t *testing.T, containers ...workloadclaims.SandboxContainer) workloadclaims.PodClaims {
	t.Helper()
	env, err := pkgallowlist.ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := workloadclaims.PodClaims{
		Version:        1,
		BootID:         strings.Repeat("b", 64),
		AssignedPodUID: "assigned",
		RuntimePodUID:  "runtime",
		SandboxID:      "sandbox",
		Revision:       1,
	}
	for _, c := range containers {
		if c.Env == nil {
			c.Env = env
		}
		if len(c.Argv) == 0 {
			c.Argv = []string{"/app"}
		}
		p.Containers = append(p.Containers, c)
		p.RuntimeExtensions = append(p.RuntimeExtensions, c.Digest)
	}
	return p
}
