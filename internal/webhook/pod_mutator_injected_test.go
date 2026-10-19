package webhook

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The secrets drop set names the exact invocations this webhook injects, so
// every container mutatePod adds must be one of them. A sidecar the drop set
// does not recognise is a foreign container, and every release in the cluster
// is refused.
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
	al := &allowlist.Allowlist{Workloads: map[string]allowlist.Workload{
		"c8s": allowlist.DigestEntry(digest, cfg.GetCertImage),
	}}

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
		injected = append(injected, workloadclaims.SandboxContainer{Digest: digest.String(), Argv: argv, Mounts: []allowlist.ObservedMount{}})
	}
	if len(injected) != 4 {
		t.Fatalf("injected %d containers, want the cert sidecar, cert-wait gate, secret fetcher, and volume fetcher", len(injected))
	}
	if left := secrets.WorkloadContainers(al, injected); len(left) != 0 {
		t.Fatalf("injected containers the drop set does not recognise: %+v", left)
	}
}
