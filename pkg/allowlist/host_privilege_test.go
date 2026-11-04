package allowlist

import (
	"fmt"
	"strings"
	"testing"
)

const hostPrivilegeDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

// mountingContainer is a pinned launch whose exact mount policy holds rules.
func mountingContainer(rules string) string {
	return fmt.Sprintf(`{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","rules":[%s]},"env":{"policy":"deny"}}`, hostPrivilegeDigest, rules)
}

func hostPrivilegeEntry(containers string) string {
	return `{"containers":[` + containers + `]}`
}

// Published ports, a capability, or a host bind declare it; nothing else does.
func TestEntriesThatDeclareHostPrivilege(t *testing.T) {
	pinned := fmt.Sprintf(pinnedContainer, hostPrivilegeDigest)
	capable := strings.TrimSuffix(pinned, "}") + `,"capabilities":["SYS_PTRACE"]}`
	for name, tc := range map[string]struct {
		entry    string
		declares bool
	}{
		"a pinned launch alone": {hostPrivilegeEntry(pinned), false},
		"published ports": {
			`{"containers":[` + pinned + `],"hostPorts":[{"protocol":"TCP","hostPort":443,"containerPort":8443}]}`,
			true,
		},
		"a capability":                   {hostPrivilegeEntry(capable), true},
		"an init container's capability": {`{"initContainers":[` + capable + `],"containers":[` + pinned + `]}`, true},
		"a host bind":                    {hostPrivilegeEntry(mountingContainer(`{"destination":"/node","kind":"host","source":"/var/lib/c8s"}`)), true},
		"a read-only node-root file":     {hostPrivilegeEntry(mountingContainer(`{"destination":"/etc/hosts","kind":"nodeRootFile","source":"/etc/hosts","readOnly":true}`)), false},
		"an emptyDir":                    {hostPrivilegeEntry(mountingContainer(`{"destination":"/scratch","kind":"emptyDir"}`)), false},
		"an unconstrained mount policy":  {hostPrivilegeEntry(fmt.Sprintf(`{"digest":%q,"command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"},"env":{"policy":"any"}}`, hostPrivilegeDigest)), false},
	} {
		t.Run(name, func(t *testing.T) {
			w, err := ParseWorkloadJSON([]byte(tc.entry))
			if err != nil {
				t.Fatal(err)
			}
			if w.DeclaresHostPrivilege() != tc.declares {
				t.Fatalf("DeclaresHostPrivilege = %t, want %t", w.DeclaresHostPrivilege(), tc.declares)
			}
		})
	}
}

// Only an exact policy carries rules, so a host rule beside any declares nothing.
func TestAHostRuleUnderAnUnconstrainedMountPolicyDeclaresNothing(t *testing.T) {
	w := Workload{Containers: []Container{{
		Mounts: MountPolicy{
			Policy: PolicyAny,
			Rules:  []MountRule{{Destination: "/node", Kind: MountHost, Source: "/var/lib/c8s"}},
		},
	}}}
	if w.DeclaresHostPrivilege() {
		t.Fatal("DeclaresHostPrivilege = true, want false: the policy constrains no mount")
	}
}
