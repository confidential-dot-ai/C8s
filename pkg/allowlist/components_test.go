package allowlist

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// componentEntry is a valid component set entry: pinned bytes, command and
// mount set, bound to role under a name the document uses.
func componentEntry(digest, role string) string {
	return `{"containers":[{"digest":"` + digest + `","role":"` + role + `",` +
		`"command":{"policy":"exact","argv":["/app/c8s","armtls-mesh"]},` +
		`"args":{"policy":"any"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir","source":"c8s-run"}]}}]}`
}

// currentSet is the set every refusal test keeps beside the failing one.
const currentSetVersion = "0.43.0"

func currentSet() string {
	return `"` + currentSetVersion + `":{"entries":{"c8s-mesh-endpoint":` + componentEntry(digestA, RoleMesh) + `}}`
}

// componentsDoc is a document with a tenant entry and the given sets.
func componentsDoc(sets ...string) string {
	return `{"schema":"` + Schema + `","workloads":{"tenant":{"containers":[` +
		`{"digest":"` + digestC + `","command":{"policy":"any"},"args":{"policy":"any"}}]}},` +
		`"components":{` + strings.Join(sets, ",") + `}}`
}

func TestComponentSetParses(t *testing.T) {
	al := mustParse(t, componentsDoc(currentSet()))
	set, listed := al.Components[currentSetVersion]
	if !listed || set.Retire != nil {
		t.Fatalf("components = %#v, want one current set", al.Components)
	}
	c := set.Entries["c8s-mesh-endpoint"].Containers[0]
	if c.Role != RoleMesh || c.Mounts.Rules[0].Source != "c8s-run" {
		t.Fatalf("set entry lost its role or its volume binding: %#v", c)
	}
}

func TestComponentSetRetires(t *testing.T) {
	retiring := `"0.42.1":{"retire":{"deadline":"2026-12-01T00:00:00Z"},"entries":{}}`
	al := mustParse(t, componentsDoc(currentSet(), retiring))
	want := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if deadline := al.Components["0.42.1"].Retire.Deadline; !deadline.Equal(want) {
		t.Fatalf("deadline = %s, want %s", deadline, want)
	}
}

// A beta release publishes a set too, so a pre-release version keys one, and
// it orders before the version it leads to.
func TestComponentSetVersionsCarryAPreRelease(t *testing.T) {
	beta := `"0.44.0-beta.1":{"entries":{}}`
	al := mustParse(t, componentsDoc(currentSet(), beta))
	if _, listed := al.Components["0.44.0-beta.1"]; !listed {
		t.Fatalf("components = %v, want the beta's set", al.Components)
	}
	if got := al.SetsInForce(time.Now()); len(got) != 2 || got[0].Version != currentSetVersion || got[1].Version != "0.44.0-beta.1" {
		t.Fatalf("sets in force = %v, want %s before the beta of 0.44.0", got, currentSetVersion)
	}
	if CompareSetVersions("0.44.0-beta.1", "0.44.0") >= 0 {
		t.Error("a beta does not order before the version it leads to")
	}
}

// An authored document is refused over a set a check refuses, naming the set;
// a served document loses that set alone and keeps the rest in force.
func TestComponentSetChecks(t *testing.T) {
	for name, set := range map[string]struct {
		version string
		json    string
	}{
		"version is not a semver":        {"0.42", `"0.42":{"entries":{}}`},
		"version has a leading zero":     {"0.042.1", `"0.042.1":{"entries":{}}`},
		"version carries build metadata": {"0.42.1+2026", `"0.42.1+2026":{"entries":{}}`},
		"version keeps its v":            {"v0.42.1", `"v0.42.1":{"entries":{}}`},
		"unsupported major version":      {"1.0.0", `"1.0.0":{"entries":{}}`},
		"retirement without a deadline":  {"0.42.1", `"0.42.1":{"retire":{},"entries":{}}`},
		"invalid entry": {"0.42.1", `"0.42.1":{"entries":{"c8s-get-cert":{"containers":[` +
			`{"digest":"` + digestB + `","command":{"policy":"exact"},"args":{"policy":"any"},` +
			`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir"}]}}]}}}`},
		"unknown role": {"0.42.1", `"0.42.1":{"entries":{"c8s-get-cert":` + componentEntry(digestB, "operator") + `}}`},
		"command left to the pod": {"0.42.1", `"0.42.1":{"entries":{"c8s-get-cert":{"containers":[` +
			`{"digest":"` + digestB + `","role":"` + RoleCredentials + `","command":{"policy":"any"},"args":{"policy":"any"},` +
			`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir"}]}}]}}}`},
		"mounts left to the pod": {"0.42.1", `"0.42.1":{"entries":{"c8s-get-cert":{"containers":[` +
			`{"digest":"` + digestB + `","role":"` + RoleCredentials + `","command":{"policy":"exact","argv":["/app/c8s"]},` +
			`"args":{"policy":"any"},"mounts":{"policy":"any"}}]}}}`},
		"a declared capability": {"0.42.1", `"0.42.1":{"entries":{"c8s-get-cert":{"containers":[` +
			`{"digest":"` + digestB + `","command":{"policy":"exact","argv":["/app/c8s"]},"args":{"policy":"deny"},` +
			`"env":{"policy":"deny"},"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir"}]},` +
			`"capabilities":["SYS_PTRACE"]}]}}}`},
		"one launch bound twice": {"0.42.1", `"0.42.1":{"entries":{` +
			`"c8s-mesh-endpoint":` + componentEntry(digestB, RoleMesh) + `,` +
			`"c8s-mesh-endpoint-2":` + componentEntry(digestB, RoleCredentials) + `}}`},
		"a node service with an init container": {"0.42.1", `"0.42.1":{"entries":{"volumed":{"nodeService":true,` +
			`"initContainers":[` + nodeServiceContainer(digestB) + `],"containers":[` + nodeServiceContainer(digestA) + `]}}}`},
		"a node service with an open environment": {"0.42.1", `"0.42.1":{"entries":{"volumed":{"nodeService":true,` +
			`"containers":[{"digest":"` + digestB + `","command":{"policy":"exact","argv":["/app/c8s","volumed"]},` +
			`"args":{"policy":"exact","argv":["--state-dir","/run/c8s"]},"env":{"policy":"any"},` +
			`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir"}]}}]}}}`},
		"a field this reader does not know": {"0.42.1", `"0.42.1":{"entries":{},"surprise":true}`},
	} {
		t.Run(name, func(t *testing.T) {
			doc := []byte(componentsDoc(currentSet(), set.json))
			for posture, parse := range map[string]func([]byte) (*Allowlist, error){
				"authored": ParseJSON,
				"stored":   ParseStoredJSON,
			} {
				err := errOf(parse(doc))
				if err == nil || !strings.Contains(err.Error(), set.version) {
					t.Errorf("the %s posture accepted the set: %v", posture, err)
				}
			}
			served, err := ParseServedJSON(doc)
			if err != nil {
				t.Fatalf("the served posture refused the document: %v", err)
			}
			if _, kept := served.Components[set.version]; kept {
				t.Error("the served posture kept the set")
			}
			if _, kept := served.Components[currentSetVersion]; !kept {
				t.Error("the served posture dropped the current set with the failing one")
			}
			if _, kept := served.Workloads["tenant"]; !kept {
				t.Error("the served posture dropped the workloads section with the failing set")
			}
		})
	}
}

// nodeServiceContainer pins everything a node service's launch must pin.
func nodeServiceContainer(digest string) string {
	return `{"digest":"` + digest + `","command":{"policy":"exact","argv":["/app/c8s","volumed"]},` +
		`"args":{"policy":"exact","argv":["--state-dir","/run/c8s"]},"env":{"policy":"exact","values":{"HOME":"/root"}},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir"}]}}`
}

func TestComponentSetAdmitsANodeService(t *testing.T) {
	set := `"0.43.0":{"entries":{"volumed":{"nodeService":true,"containers":[` + nodeServiceContainer(digestA) + `]}}}`
	al := mustParse(t, componentsDoc(set))
	if !al.Components["0.43.0"].Entries["volumed"].NodeService {
		t.Fatal("the node service mark was lost")
	}
}

// The two fields a set entry adds are refused under workloads on the write
// path and dropped from a served document, and a mount rule naming a pod
// volume is refused in every posture there.
func TestWorkloadsSectionRefusesComponentFields(t *testing.T) {
	doc := func(entry string) []byte {
		return []byte(`{"schema":"` + Schema + `","workloads":{"tenant":` + entry + `}}`)
	}
	pinned := `{"containers":[{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/app"]},` +
		`"args":{"policy":"deny"},"env":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir"}]}}]`

	role := doc(`{"containers":[{"digest":"` + digestA + `","role":"` + RoleMesh + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`)
	if err := errOf(ParseJSON(role)); err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("an authored entry bound a role: %v", err)
	}
	served, err := ParseServedJSON(role)
	if err != nil {
		t.Fatal(err)
	}
	if got := served.Workloads["tenant"].Containers[0].Role; got != noRole {
		t.Errorf("a served workload entry kept the %q role", got)
	}

	nodeService := doc(pinned + `,"nodeService":true}`)
	if err := errOf(ParseJSON(nodeService)); err == nil || !strings.Contains(err.Error(), "nodeService") {
		t.Errorf("an authored entry claimed a node service: %v", err)
	}
	served, err = ParseServedJSON(nodeService)
	if err != nil {
		t.Fatal(err)
	}
	if served.Workloads["tenant"].NodeService {
		t.Error("a served workload entry kept the node service mark")
	}

	volume := doc(`{"containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir","source":"c8s-run"}]}}]}`)
	for posture, parse := range map[string]func([]byte) (*Allowlist, error){
		"authored": ParseJSON,
		"served":   ParseServedJSON,
	} {
		if err := errOf(parse(volume)); err == nil || !strings.Contains(err.Error(), "volume") {
			t.Errorf("the %s posture accepted a workload entry binding a pod volume: %v", posture, err)
		}
	}
}

// A set round-trips through the canonical form, whatever order its entries
// and sets arrive in.
func TestComponentSetsRoundTripCanonical(t *testing.T) {
	retiring := `"0.42.1":{"retire":{"deadline":"2026-12-01T00:00:00Z"},"entries":{"c8s-get-cert":` +
		componentEntry(digestB, RoleCredentials) + `}}`
	al := mustParse(t, componentsDoc(currentSet(), retiring))
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte(`"deadline":"2026-12-01T00:00:00Z"`)) {
		t.Fatalf("the canonical form spells the deadline differently: %s", canonical)
	}
	again, err := ParseJSON(canonical)
	if err != nil {
		t.Fatalf("re-parse canonical: %v", err)
	}
	second, err := again.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, second) {
		t.Fatalf("canonical form not stable across a round trip:\n%s\n%s", canonical, second)
	}
	reordered := mustParse(t, componentsDoc(retiring, currentSet()))
	other, err := reordered.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, other) {
		t.Fatal("canonical form depends on the order the sets arrive in")
	}
}

// A deadline has one spelling, so the signed bytes of an instant are fixed.
func TestDeadlineSpellings(t *testing.T) {
	for _, tc := range []struct {
		text   string
		admits bool
	}{
		{"2026-12-01T00:00:00Z", true},
		{"2026-12-01T00:00:00+00:00", false},
		{"2026-12-01T01:00:00+01:00", false},
		{"2026-12-01T00:00:00.500Z", false},
		{"2026-12-01t00:00:00z", false},
		{"2026-12-01T00:00:00", false},
		{"2026-12-01", false},
		{"", false},
	} {
		var d Deadline
		err := d.UnmarshalJSON([]byte(`"` + tc.text + `"`))
		if tc.admits != (err == nil) {
			t.Errorf("deadline %q: error = %v, want admitted = %v", tc.text, err, tc.admits)
			continue
		}
		if !tc.admits {
			continue
		}
		marshaled, err := d.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(marshaled) != `"`+tc.text+`"` {
			t.Errorf("deadline %q marshals as %s", tc.text, marshaled)
		}
	}
	var d Deadline
	if err := d.UnmarshalJSON([]byte(`1764547200`)); err == nil {
		t.Error("a deadline that is not a string was admitted")
	}
}

func errOf(_ *Allowlist, err error) error { return err }
