package allowlist

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const capabilityDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

// capabilitiesEntry is an entry of one pinned container declaring caps.
func capabilitiesEntry(caps string) string {
	return fmt.Sprintf(`{"containers":[{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"}%s}]}`, capabilityDigest, caps)
}

func capabilitiesDocument(caps string) []byte {
	return []byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":` + capabilitiesEntry(caps) + `}}`)
}

func mustCanonicalJSON(t *testing.T, doc []byte) []byte {
	t.Helper()
	al, err := ParseJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCapabilitiesAreCanonicalAndOmittedWhenEmpty(t *testing.T) {
	want := `"capabilities":["BPF","SYSLOG","SYS_PTRACE"]`
	if got := mustCanonicalJSON(t, capabilitiesDocument(`,"capabilities":["SYS_PTRACE","SYSLOG","BPF"]`)); !strings.Contains(string(got), want) {
		t.Fatalf("canonical = %s, want it to carry %s", got, want)
	}
	for _, caps := range []string{``, `,"capabilities":[]`} {
		if got := mustCanonicalJSON(t, capabilitiesDocument(caps)); strings.Contains(string(got), "capabilities") {
			t.Fatalf("canonical = %s, want no capabilities key", got)
		}
	}
}

// Containers of one digest differing only in what they declare sort in one order.
func TestCapabilitiesOrderContainersSharingADigest(t *testing.T) {
	container := func(name string) string {
		return fmt.Sprintf(`{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"capabilities":[%q]}`, capabilityDigest, name)
	}
	document := func(first, second string) []byte {
		return []byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[` + container(first) + `,` + container(second) + `]}}}`)
	}
	written := mustCanonicalJSON(t, document("SYS_PTRACE", "SYSLOG"))
	reversed := mustCanonicalJSON(t, document("SYSLOG", "SYS_PTRACE"))
	if !bytes.Equal(written, reversed) {
		t.Fatalf("canonical forms differ by input order:\n%s\n%s", written, reversed)
	}
}

// A write is refused unless every capability is declarable and declared once;
// a served document drops them instead.
func TestCapabilitiesRefuseWhatNoEntryDeclares(t *testing.T) {
	// What does not decode is one empty name, whatever made it undecodable.
	const notANameList = "capabilities is not a list of capability names"
	type refusal struct{ caps, want string }
	cases := map[string]refusal{
		"unknown name":     {`["SYS_SUPERPOWER"]`, `"SYS_SUPERPOWER" is not a capability an entry may declare`},
		"CAP_ prefix":      {`["CAP_SYS_PTRACE"]`, `"CAP_SYS_PTRACE" is not a capability an entry may declare`},
		"lower case":       {`["sys_ptrace"]`, `"sys_ptrace" is not a capability an entry may declare`},
		"runtime default":  {`["CHOWN"]`, `"CHOWN" is not a capability an entry may declare`},
		"rewrites rules":   {`["NET_ADMIN"]`, `"NET_ADMIN" is not a capability an entry may declare`},
		"takes identity":   {`["SETUID"]`, `"SETUID" is not a capability an entry may declare`},
		"one undeclarable": {`["SYS_PTRACE","NET_RAW"]`, `"NET_RAW" is not a capability an entry may declare`},
		"declared twice":   {`["SYS_PTRACE","SYS_PTRACE"]`, "capability SYS_PTRACE is declared twice"},
		"empty name":       {`[""]`, notANameList},
		"not a list":       {`"SYS_PTRACE"`, notANameList},
		"not a name":       {`[19]`, notANameList},
		"null name":        {`[null]`, notANameList},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseJSON(capabilitiesDocument(`,"capabilities":` + tc.caps))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseJSON = %v, want it to name %q", err, tc.want)
			}
			if _, err := ParseWorkloadJSON([]byte(capabilitiesEntry(`,"capabilities":` + tc.caps))); err == nil {
				t.Fatalf("ParseWorkloadJSON accepted capabilities %s", tc.caps)
			}
			served, err := ParseServedJSON(capabilitiesDocument(`,"capabilities":` + tc.caps))
			if err != nil {
				t.Fatalf("ParseServedJSON = %v, want the document kept", err)
			}
			w, ok := served.Workloads["w"]
			if !ok {
				t.Fatal("the entry was dropped, want only its capabilities dropped")
			}
			if got := w.Containers[0].Capabilities; got != nil {
				t.Fatalf("capabilities = %v, want them dropped", got)
			}
		})
	}
}

// A strict parse refuses unpinned capabilities; a served one drops them.
func TestCapabilitiesRequireAPinnedLaunch(t *testing.T) {
	for name, container := range map[string]string{
		"command any":       `{"digest":%q,"command":{"policy":"any"},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"capabilities":["SYS_PTRACE"]}`,
		"args any":          `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"any"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"capabilities":["SYS_PTRACE"]}`,
		"mounts any":        `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"any"},"env":{"policy":"deny"},"capabilities":["SYS_PTRACE"]}`,
		"env any":           `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"any"},"capabilities":["SYS_PTRACE"]}`,
		"no env policy":     `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"capabilities":["SYS_PTRACE"]}`,
		"sibling container": `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"capabilities":["SYS_PTRACE"]},{"digest":"` + digestB + `","command":{"policy":"any"},"args":{"policy":"any"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			entry := fmt.Sprintf(`{"containers":[`+container+`]}`, capabilityDigest)
			doc := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":` + entry + `}}`)
			if _, err := ParseJSON(doc); err == nil || !strings.Contains(err.Error(), "declared capabilities need every container to pin its launch") {
				t.Fatalf("ParseJSON = %v, want a pin refusal", err)
			}
			if _, err := ParseWorkloadJSON([]byte(entry)); err == nil {
				t.Fatal("ParseWorkloadJSON accepted an unpinned entry declaring a capability")
			}
			served, err := ParseServedJSON(doc)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range served.Workloads["w"].Containers {
				if c.Capabilities != nil {
					t.Fatalf("capabilities = %v, want them dropped", c.Capabilities)
				}
			}
		})
	}
}

// A declaration adds to the set a container holds anyway.
func TestTheDefaultSetIsNotDeclarable(t *testing.T) {
	for _, name := range DefaultCapabilities {
		if slices.Contains(declarableCapabilities, name) {
			t.Errorf("%s is both held by default and declarable", name)
		}
	}
}

// The capabilities the runtime wrapper's floor refuses are the four that defeat
// the pod's packet rules or take a platform role's identity, plus any name
// neither list holds.
func TestUndeclarableCapability(t *testing.T) {
	for _, name := range []string{
		"NET_ADMIN",
		"NET_RAW",
		"SETGID",
		"SETUID",
		"SOMETHING_THE_LISTS_DO_NOT_NAME",
	} {
		if !UndeclarableCapability(name) {
			t.Errorf("%s is declarable or held by default", name)
		}
	}
	for _, name := range []string{
		"CHOWN",
		"SYS_ADMIN",
	} {
		if UndeclarableCapability(name) {
			t.Errorf("%s is neither held by default nor declarable", name)
		}
	}
}

// The record the runtime wrapper reads is what each declaration admitting a
// launch declares for it.
func TestDeclaredCapabilities(t *testing.T) {
	al, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{` +
		`"w":` + capabilitiesEntry(`,"capabilities":["SYS_PTRACE"]`) + `,` +
		`"b":` + capabilitiesEntry(`,"capabilities":["BPF"]`) + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	env, err := ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	index := al.BuildIndex()
	launch := RunningContainer{Digest: capabilityDigest, Argv: []string{"/app"}, Mounts: []ObservedMount{}, Env: env}
	want := [][]string{{"BPF"}, {"SYS_PTRACE"}}
	got := index.DeclaredCapabilities(launch)
	slices.SortFunc(got, slices.Compare)
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("DeclaredCapabilities = %v, want %v", got, want)
	}
	launch.Argv = []string{"/other"}
	if got := index.DeclaredCapabilities(launch); got != nil {
		t.Fatalf("a launch no declaration admits holds %v", got)
	}
}

// One declaration must declare every capability asked for and admit the launch.
func TestGrantsCapabilities(t *testing.T) {
	open := fmt.Sprintf(`{"containers":[{"digest":%q,"command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]}`, capabilityDigest)
	index := func(t *testing.T, workloads string) *Index {
		t.Helper()
		al, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{` + workloads + `}}`))
		if err != nil {
			t.Fatal(err)
		}
		return al.BuildIndex()
	}
	declaring := `"w":` + capabilitiesEntry(`,"capabilities":["SYS_PTRACE"]`)
	env, err := ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		index *Index
		argv  []string
		caps  []string
		want  bool
	}{
		{name: "the declaring launch", index: index(t, declaring), want: true},
		{name: "a capability it does not declare", index: index(t, declaring), caps: []string{"BPF"}},
		{name: "another launch of the same image", index: index(t, declaring), argv: []string{"/other"}},
		{name: "an open entry sharing the digest", index: index(t, declaring+`,"open":`+open), argv: []string{"/other"}},
		{name: "no capability to grant", index: index(t, declaring), caps: []string{}},
		{name: "no allowlist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := tc.argv
			if argv == nil {
				argv = []string{"/app"}
			}
			caps := tc.caps
			if caps == nil {
				caps = []string{"SYS_PTRACE"}
			}
			launch := RunningContainer{Digest: capabilityDigest, Argv: argv, Mounts: []ObservedMount{}, Env: env}
			if got := tc.index.GrantsCapabilities(launch, caps); got != tc.want {
				t.Fatalf("GrantsCapabilities(%s) = %t, want %t", tc.name, got, tc.want)
			}
		})
	}
}
