package allowlist

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// roleIndex builds an index over one declared container bound to role.
func roleIndex(t *testing.T, role string, argv []string) *Index {
	t.Helper()
	digest, err := types.ParseDigest(digestA)
	if err != nil {
		t.Fatal(err)
	}
	a := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"entry": {Containers: []Container{{
		Digest:  digest,
		Role:    role,
		Command: ArgvPolicy{Policy: PolicyExact, Argv: argv},
		Args:    ArgvPolicy{Policy: PolicyDeny},
		Mounts:  MountPolicy{Policy: PolicyAny},
	}}}}}
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	return a.BuildIndex()
}

// A role is bound to the whole verified launch, not to the bytes alone.
func TestRoleOfBindsAVerifiedLaunch(t *testing.T) {
	argv := []string{"/usr/local/bin/c8s", "get-cert"}
	index := roleIndex(t, "get-cert", argv)

	launch := RunningContainer{Digest: digestA, Argv: argv, Mounts: []ObservedMount{}}
	if got := index.RoleOf(launch); got != "get-cert" {
		t.Fatalf("RoleOf = %q, want get-cert", got)
	}
	// The args policy is deny, so an extra argument leaves the declaration
	// unsatisfied — and the role unbound.
	if got := index.RoleOf(RunningContainer{Digest: digestA, Argv: append(argv, "--debug"), Mounts: []ObservedMount{}}); got != "" {
		t.Fatalf("an unadmitted argv took the %q role", got)
	}
	if got := index.RoleOf(RunningContainer{Digest: digestB, Argv: argv, Mounts: []ObservedMount{}}); got != "" {
		t.Fatalf("another image took the %q role", got)
	}
	if got := (*Index)(nil).RoleOf(launch); got != "" {
		t.Fatalf("an empty policy bound the %q role", got)
	}
}

// Two declarations binding different roles to one launch bind none: an
// ambiguous role is no role.
func TestRoleOfRefusesAnAmbiguousRole(t *testing.T) {
	argv := []string{"/usr/local/bin/c8s", "get-cert"}
	digest, err := types.ParseDigest(digestA)
	if err != nil {
		t.Fatal(err)
	}
	a := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"cert": {Containers: []Container{{Digest: digest, Role: "get-cert", Command: ArgvPolicy{Policy: PolicyAny}, Args: ArgvPolicy{Policy: PolicyAny}, Mounts: MountPolicy{Policy: PolicyAny}}}},
		"mesh": {Containers: []Container{{Digest: digest, Role: "mesh", Command: ArgvPolicy{Policy: PolicyAny}, Args: ArgvPolicy{Policy: PolicyAny}, Mounts: MountPolicy{Policy: PolicyAny}}}},
	}}
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	if got := a.BuildIndex().RoleOf(RunningContainer{Digest: digestA, Argv: argv, Mounts: []ObservedMount{}}); got != "" {
		t.Fatalf("two declarations bound the %q role", got)
	}
}

// A role never travels on the wire: it is absent from the canonical document,
// an operator-authored document naming one is refused, and a served document
// naming one yields no role.
func TestRoleIsBoundByBootConfigAlone(t *testing.T) {
	index := roleIndex(t, "mesh", []string{"/usr/local/bin/armtls-mesh"})
	launch := RunningContainer{Digest: digestA, Argv: []string{"/usr/local/bin/armtls-mesh"}, Mounts: []ObservedMount{}}
	if index.RoleOf(launch) != "mesh" {
		t.Fatal("a boot config bound no role")
	}

	wire := `{"schema":"` + Schema + `","workloads":{"entry":{"containers":[` +
		`{"digest":"` + digestA + `","role":"mesh","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"},"env":{"policy":"any"}}` +
		`]}}}`
	if _, err := ParseJSON([]byte(wire)); err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("an authored document naming a role was accepted: %v", err)
	}
	served, err := ParseServedJSON([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	if got := served.BuildIndex().RoleOf(launch); got != "" {
		t.Fatalf("a served document bound the %q role", got)
	}
}
