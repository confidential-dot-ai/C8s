package webhook

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The secrets drop set holds the containers a node binds a platform role to,
// so every container mutatePod adds must be one the node grants a role
// (internal/helmchart base_roles_test.go). A sidecar left without one is a
// foreign container, and every release in the cluster is refused.
func TestInjectedContainersAreTheSecretsDropSet(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/run/nri-image-policy"
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights=/tenant-a/volumes/weights"}},
	}, cfg)

	digest, err := types.ParseDigest("sha256:9999999999999999999999999999999999999999999999999999999999999999")
	if err != nil {
		t.Fatal(err)
	}
	var injected []workloadclaims.SandboxContainer
	for _, c := range pod.Spec.InitContainers {
		if !workloadclaims.IsInjectedContainerName(c.Name) {
			continue
		}
		// The effective argv is the image ENTRYPOINT followed by Args unless
		// Command overrides it.
		argv := c.Command
		if len(argv) == 0 {
			argv = append([]string{secrets.InjectedBinary}, c.Args...)
		}
		role := "credentials"
		if c.Name == workloadclaims.MeshContainerName {
			role = "mesh"
		}
		injected = append(injected, workloadclaims.SandboxContainer{Digest: digest.String(), Argv: argv, Mounts: []allowlist.ObservedMount{}, Role: role})
	}
	if len(injected) != 5 {
		t.Fatalf("injected %d containers, want the mesh endpoint, cert sidecar, cert-wait gate, secret fetcher, and volume fetcher", len(injected))
	}
	if left := secrets.WorkloadContainers(injected); len(left) != 0 {
		t.Fatalf("injected containers the drop set does not recognise: %+v", left)
	}
}
