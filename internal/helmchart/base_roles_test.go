package helmchart

import (
	"slices"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
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

// injectedRoleLaunches is one launch per injected container that runs on a
// reserved uid, with the per-pod arguments the webhook appends
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

			// The credentials and mesh roles are dropped from the workload
			// match, so they are granted only with the mount table the
			// webhook gives the invocation: a pod's own container running one
			// with a mount of its choosing holds no role and stays in the match.
			for name, w := range base.Workloads {
				for i, c := range w.Containers {
					if (c.Role == "credentials" || c.Role == "mesh") && c.Mounts.Policy != pkgallowlist.PolicyExact {
						t.Errorf("container %d of %s grants the %s role with mounts %q, want exact", i, name, c.Role, c.Mounts.Policy)
					}
				}
			}
			// A component shape pins the environment too
			// (component_mounts_test.go); the floor's role entries pin the
			// mounts alone, so they are checked here.
			if name == "bootstrap floor digests" {
				checkFloorGateMounts(t, base)
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

// checkFloorGateMounts checks the floor grants the cert-wait gate and the
// mesh endpoint their roles under the webhook's volume alone.
func checkFloorGateMounts(t *testing.T, base pkgallowlist.Allowlist) {
	t.Helper()
	dir := workloadclaims.MemberCertDir
	mesh := []string{"/app/c8s", "armtls-mesh", "--cert-path=" + dir + "/tls.crt", "--key-path=" + dir + "/tls.key", "--ca-path=" + dir + "/ca.crt"}
	certs := pkgallowlist.ObservedMount{Destination: workloadclaims.MemberCertDir, Volume: "c8s-certs", Class: pkgallowlist.MountEmptyDir, Storage: pkgallowlist.MountMemory}
	scratch := pkgallowlist.ObservedMount{Destination: "/scratch", Volume: "scratch", Class: pkgallowlist.MountEmptyDir, Storage: pkgallowlist.MountUnknown}
	gate := []string{"/c8s", "probe-file", "--wait", "--timeout=3m0s", workloadclaims.MemberCertDir + "/tls.crt"}
	// The webhook refuses a pod's own mount of c8s-certs, not of
	// another memory volume at the same destination, so the grant
	// names the volume.
	own := pkgallowlist.ObservedMount{Destination: workloadclaims.MemberCertDir, Volume: "own", Class: pkgallowlist.MountEmptyDir, Storage: pkgallowlist.MountMemory}
	index := base.BuildIndex()
	for _, tc := range []struct {
		name   string
		digest string
		argv   []string
		mounts []pkgallowlist.ObservedMount
		want   string
	}{
		{"the webhook's gate", roleOperatorDigest, gate, []pkgallowlist.ObservedMount{certs}, "credentials"},
		{"the gate with a disk volume of the pod's own beside", roleOperatorDigest, gate, []pkgallowlist.ObservedMount{certs, scratch}, ""},
		{"the gate with a memory volume of the pod's own at the certificate destination", roleOperatorDigest, gate, []pkgallowlist.ObservedMount{own}, ""},
		{"the webhook's mesh endpoint", roleMeshDigest, mesh, []pkgallowlist.ObservedMount{certs}, "mesh"},
		{"the mesh endpoint with a disk volume of the pod's own beside", roleMeshDigest, mesh, []pkgallowlist.ObservedMount{certs, scratch}, ""},
		{"the mesh endpoint with a memory volume of the pod's own at the certificate destination", roleMeshDigest, mesh, []pkgallowlist.ObservedMount{own}, ""},
	} {
		probe := pkgallowlist.RunningContainer{Digest: tc.digest, Argv: tc.argv, Mounts: tc.mounts}
		if got := index.RoleOf(probe); got != tc.want {
			t.Errorf("%s holds the role %q, want %q", tc.name, got, tc.want)
		}
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

// The router pod's own containers hold the same roles, and the chart renders
// that pod itself. Its nginx comes from Docker Hub, which an image reference
// may name explicitly, so the lane's floor labels the front door's digest
// docker.io/<repository>@<digest> while the component value names the bare
// repository.
const roleNginxDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000e3"
const roleTenantNginxDigest = "sha256:e400000000000000000000000000000000000000000000000000000000000000"

// routerPodRoles is the role every container of the rendered router pod takes.
var routerPodRoles = map[string]string{
	"c8s-mesh":        "mesh",
	"c8s-cert":        "credentials",
	"c8s-cert-wait":   "credentials",
	"allowlist-proxy": "credentials",
	"nginx":           "router",
	"cds-attest":      "upstream",
	"acme":            "acme",
}

// TestChartBaseGrantsTheRouterPodItsRoles proves the rendered base grants
// every container of the router pod the role it runs as, whether a digest
// reaches that base as a derived component image or as a hand-pinned
// bootstrapAllowlist entry labelled the way the cluster lane's store scan
// writes it.
func TestChartBaseGrantsTheRouterPodItsRoles(t *testing.T) {
	digestArgs := []string{
		"--set-string", "armtlsMesh.image.digest=" + roleMeshDigest,
		"--set-string", "image.digest=" + roleOperatorDigest,
		"--set-string", "router.nginx.image.digest=" + roleNginxDigest,
		"--set", "router.attest.enabled=true",
		"--set-string", "router.publicTLS.mode=acme",
		"--set", "router.san={lb.example.com}",
	}
	// Tag-referenced C8s images and a registry-qualified front door, as the
	// lane's containerd store lists what it loaded and pulled.
	floorArgs := append(
		anyArgvEntryArgs("mesh-floor", roleMeshDigest, "ghcr.io/confidential-dot-ai/armtls-mesh:it"),
		anyArgvEntryArgs("operator-floor", roleOperatorDigest, "ghcr.io/confidential-dot-ai/c8s-operator:it")...,
	)
	// Named as the lane's store scan names it, so it overrides the front door's shape.
	floorArgs = append(floorArgs,
		anyArgvEntryArgs("nginx-unprivileged-"+roleNginxDigest[len("sha256:"):][:12], roleNginxDigest, "docker.io/nginxinc/nginx-unprivileged@"+roleNginxDigest)...,
	)
	// A tenant's nginx from the same repository, as the lane's workload image.
	floorArgs = append(floorArgs,
		anyArgvEntryArgs("nginx-tenant-floor", roleTenantNginxDigest, "docker.io/nginxinc/nginx-unprivileged@"+roleTenantNginxDigest)...,
	)
	// The webpki front door and its attestation sidecar mount the operator's
	// Secret, which the base pins as data below the reserved prefix.
	webpkiArgs := append(slices.Clone(digestArgs),
		"--set-string", "router.publicTLS.mode=webpki",
		"--set-string", "router.publicTLS.secretName=router-public-tls",
	)
	// Pinned operator keys put one more data mount on cds-attest, so the base
	// the same values render must name it.
	operatorKeysArgs := append(slices.Clone(digestArgs),
		"--set-string", "cds.operatorKeys=-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
	)
	operatorKeysArgs = append(operatorKeysArgs, floorArgs...)
	cases := map[string][]string{
		"derived component digests": append(digestArgs, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"),
		"bootstrap floor digests":   append(digestArgs, floorArgs...),
		"webpki front door":         append(webpkiArgs, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"),
		"pinned operator keys":      operatorKeysArgs,
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
			base := cfg.Allowlist.Base.BuildIndex()
			pins := componentPins(t, out, args)
			pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
			for _, container := range append(slices.Clone(pod.InitContainers), pod.Containers...) {
				want, held := routerPodRoles[container.Name]
				if !held {
					t.Errorf("router container %q holds no platform role, so the enforcer refuses the pod", container.Name)
					continue
				}
				launch := renderedLaunch(t, pod, container, pins[digestOf(container.Image)])
				if got := base.RoleOf(launch); got != want {
					t.Errorf("the base grants %s the role %q, want %q", container.Name, got, want)
				}
				// A role container of this namespace runs only under an entry
				// that pins its mounts (internal/cmds/nri-image-policy,
				// requireRoleOnlyPod).
				if !base.BindsRoleMounts(launch, want) {
					t.Errorf("the base grants %s the %s role under no entry that pins its mounts", container.Name, want)
				}
			}
		})
	}
}
