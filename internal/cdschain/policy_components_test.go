package cdschain

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// componentSetDocument is a document whose one set declares the sidecar under
// the given command policy; "exact" is what a set entry must pin.
func componentSetDocument(commandPolicy string) string {
	digest := "sha256:" + strings.Repeat("ab", 32)
	return `{"schema":"` + allowlist.Schema + `","workloads":{},"components":{"0.43.0":{"entries":{` +
		`"c8s-mesh-endpoint":{"containers":[{"digest":"` + digest + `","role":"mesh",` +
		`"command":{"policy":"` + commandPolicy + `","argv":["/app/c8s","armtls-mesh"]},` +
		`"args":{"policy":"any"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir","source":"c8s-run"}]}}]}` +
		`}}}}`
}

// The log re-parses a policy entry under the authored posture, so a set no
// reader would judge never reaches a replica's state, however it was signed.
func TestApplyPolicyJudgesComponentSets(t *testing.T) {
	for _, tc := range []struct {
		name          string
		commandPolicy string
		applies       bool
	}{
		{"a set pinning its command", "exact", true},
		{"a set leaving its command to the pod", "any", false},
	} {
		f := newFixture(t)
		document := []byte(componentSetDocument(tc.commandPolicy))
		if al, err := allowlist.ParseJSON(document); err == nil {
			if document, err = al.Canonical(); err != nil {
				t.Fatal(err)
			}
		}
		entry, err := Sign(f.op, Body{
			Cluster: "lane",
			Seq:     1,
			Prev:    f.state.Head.Hash,
			Type:    TypePolicy,
			Payload: mustJSON(t, Policy{Allowlist: document}),
		})
		if err != nil {
			t.Fatal(err)
		}
		next, err := f.state.Apply(entry)
		if tc.applies != (err == nil) {
			t.Fatalf("%s: Apply = %v, want applied = %v", tc.name, err, tc.applies)
		}
		if tc.applies && len(next.Policy) == 0 {
			t.Fatalf("%s: applied without storing the policy", tc.name)
		}
	}
}
