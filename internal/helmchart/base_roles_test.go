package helmchart

import (
	"slices"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The reserved uids of the injected platform roles carry no identity of their
// own: the enforcer grants a role from the node's base allowlist alone
// (internal/cmds/nri-image-policy/roles.go), so a base naming no role for an
// injected container refuses it on the reserved uid it runs as. These tests
// pin that the install lane's rendered base names those roles, on the same
// shape entries that admit them.

const (
	roleMeshDigest     = "sha256:00000000000000000000000000000000000000000000000000000000000000e1"
	roleOperatorDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000e2"
)

// platformInvocations is one invocation per injected container that runs on a
// reserved uid, with the role the base must grant it
// (internal/webhook/pod_mutator.go).
func platformInvocations() []struct {
	role string
	argv []string
} {
	return []struct {
		role string
		argv []string
	}{
		{"mesh", []string{"/app/c8s", "armtls-mesh"}},
		{"credentials", []string{"/c8s", "get-cert"}},
		{"credentials", []string{"/c8s", "probe-file"}},
		{"credentials", []string{"/c8s", "get-secret"}},
		{"credentials", []string{"/c8s", "get-volume"}},
	}
}

// otherSubcommandArgvs are invocations of the same images that hold no role:
// each role rides on the component's own subcommand.
var otherSubcommandArgvs = [][]string{
	{"/c8s", "operator"},
	{"/c8s", "cds"},
}

// TestChartBaseGrantsInjectedRoles proves the worker's base grants each
// injected container its role, whether the digest reaches the base as a
// derived component image or as a hand-pinned bootstrapAllowlist entry (what
// the cluster integration lane renders), and that no other subcommand of those
// images takes a role.
func TestChartBaseGrantsInjectedRoles(t *testing.T) {
	cases := map[string][]string{
		"derived component digests": {
			"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
			"--set-string", "armtlsMesh.image.digest=" + roleMeshDigest,
			"--set-string", "image.digest=" + roleOperatorDigest,
		},
		// Tag-referenced entries: the lane scans the node's image store, so
		// its floor names the loaded images by tag and the component values
		// carry no digest.
		"bootstrap floor digests": append(
			anyArgvEntryArgs("mesh-floor", roleMeshDigest, "ghcr.io/confidential-dot-ai/armtls-mesh:it"),
			anyArgvEntryArgs("operator-floor", roleOperatorDigest, "ghcr.io/confidential-dot-ai/c8s-operator:it")...,
		),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base

			for _, want := range platformInvocations() {
				if got := baseRoleFor(base, want.argv); got != want.role {
					t.Errorf("the base grants %v the role %q, want %q", want.argv, got, want.role)
				}
			}
			for _, argv := range otherSubcommandArgvs {
				if got := baseRoleFor(base, argv); got != "" {
					t.Errorf("%v took the %q role, want none: only a pinned subcommand holds one", argv, got)
				}
			}

			// A role never travels on the wire (pkg/allowlist drops it from
			// JSON), so no served entry carries one.
			for name, w := range renderedSeed(t, out).Workloads {
				for _, c := range w.Containers {
					if c.Role != "" {
						t.Errorf("seed entry %s carries the role %q, which the JSON ingest drops", name, c.Role)
					}
				}
			}
		})
	}
}

// baseRoleFor is the role the base's own entries carry for the invocation, or
// "" when no entry pins that command. Two entries disagreeing is reported as a
// conflict rather than a role.
func baseRoleFor(base pkgallowlist.Allowlist, argv []string) string {
	var roles []string
	for _, w := range base.Workloads {
		for _, c := range w.Containers {
			if c.Command.Policy != pkgallowlist.PolicyExact || !slices.Equal(c.Command.Argv, argv) {
				continue
			}
			if !slices.Contains(roles, c.Role) {
				roles = append(roles, c.Role)
			}
		}
	}
	if len(roles) != 1 {
		return ""
	}
	return roles[0]
}
