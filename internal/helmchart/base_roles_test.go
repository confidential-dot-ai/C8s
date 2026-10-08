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
// pin that the install lane's rendered base names those roles.

const (
	roleMeshDigest     = "sha256:00000000000000000000000000000000000000000000000000000000000000e1"
	roleOperatorDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000e2"
)

// injectedRoleLaunch is an injected container as the enforcer observes it: the
// bytes, the argv containerd resolves (image entrypoint plus the injector's
// arguments) and the role the base must grant it.
type injectedRoleLaunch struct {
	role   string
	digest string
	argv   []string
}

func (l injectedRoleLaunch) container() pkgallowlist.RunningContainer {
	return pkgallowlist.RunningContainer{Digest: l.digest, Argv: l.argv, Mounts: []pkgallowlist.ObservedMount{}}
}

// injectedRoleLaunches is one launch per injected container that runs on a
// reserved uid, with the per-pod arguments the webhook appends
// (internal/webhook/pod_mutator.go).
func injectedRoleLaunches(meshDigest, operatorDigest string) []injectedRoleLaunch {
	return []injectedRoleLaunch{
		{"mesh", meshDigest, []string{"/app/c8s", "armtls-mesh", "--cert-path=/etc/c8s/certs/tls.crt"}},
		{"credentials", operatorDigest, []string{"/c8s", "get-cert", "--no-san"}},
		{"credentials", operatorDigest, []string{"/c8s", "probe-file", "--wait", "/run/c8s/certs/tls.crt"}},
		{"credentials", operatorDigest, []string{"/c8s", "get-secret", "--out-dir=/run/c8s/secrets"}},
		{"credentials", operatorDigest, []string{"/c8s", "get-volume", "--volume=data"}},
	}
}

// otherSubcommandArgvs are launches of the same images that hold no role: each
// role entry pins the component's own subcommand.
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
			cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
			base := cfg.Allowlist.Base.BuildIndex()

			for _, launch := range injectedRoleLaunches(roleMeshDigest, roleOperatorDigest) {
				if got := base.RoleOf(launch.container()); got != launch.role {
					t.Errorf("the base grants %v the role %q, want %q", launch.argv, got, launch.role)
				}
			}
			for _, argv := range otherSubcommandArgvs {
				for _, digest := range []string{roleMeshDigest, roleOperatorDigest} {
					launch := injectedRoleLaunch{
						digest: digest,
						argv:   argv,
					}
					if got := base.RoleOf(launch.container()); got != "" {
						t.Errorf("%v took the %q role, want none: only a pinned subcommand holds one", argv, got)
					}
				}
			}

			// A role never travels on the wire (pkg/allowlist drops it from
			// JSON), so the role entries stay out of CDS's served seed.
			seed := renderedSeed(t, out)
			for _, name := range []string{"c8s-mesh-endpoint", "c8s-get-cert", "c8s-cert-wait", "c8s-get-secret", "c8s-get-volume"} {
				if _, ok := seed.Workloads[name]; ok {
					t.Errorf("seed carries the role entry %q, whose role the JSON ingest drops", name)
				}
			}
		})
	}
}

// The router pod's own containers hold the same roles, and the chart renders
// that pod itself. Its nginx comes from Docker Hub, which an image reference
// may name explicitly, so the lane's floor labels the front door's digest
// docker.io/<repository>@<digest> while the component value names the bare
// repository.
const roleNginxDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000e3"

// routerPodRoles is the role every container of the rendered router pod takes.
var routerPodRoles = map[string]string{
	"c8s-mesh":        "mesh",
	"c8s-cert":        "credentials",
	"c8s-cert-wait":   "credentials",
	"allowlist-proxy": "credentials",
	"nginx":           "router",
	"cds-attest":      "router",
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
	floorArgs = append(floorArgs,
		anyArgvEntryArgs("nginx-floor", roleNginxDigest, "docker.io/nginxinc/nginx-unprivileged@"+roleNginxDigest)...,
	)
	cases := map[string][]string{
		"derived component digests": append(digestArgs, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"),
		"bootstrap floor digests":   append(digestArgs, floorArgs...),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
			base := cfg.Allowlist.Base.BuildIndex()
			pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
			for _, container := range append(slices.Clone(pod.InitContainers), pod.Containers...) {
				want, held := routerPodRoles[container.Name]
				if !held {
					t.Errorf("router container %q holds no platform role, so the enforcer refuses the pod", container.Name)
					continue
				}
				if got := base.RoleOf(observedLaunch(container)); got != want {
					t.Errorf("the base grants %s the role %q, want %q", container.Name, got, want)
				}
			}
		})
	}
}
