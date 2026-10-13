package helmchart

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const routerEntry = "c8s-router"

var c8sDigest = "sha256:" + strings.Repeat("1", 64)

// digestArgs pins the c8s image outside the baked shape. deriveComponents
// gives it the any-argv entry that lets get-cert be dropped as injected.
var digestArgs = []string{
	"--set", "image.digest=" + c8sDigest,
	"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
}

// running is the set the node inventory reports for a rendered pod: a pod
// command replaces the entrypoint, which is /c8s for the c8s image and
// irrelevant to the any-argv entries of the others. Mounts are reported as
// platform-only.
func running(pod corev1.PodSpec) []workloadclaims.SandboxContainer {
	var out []workloadclaims.SandboxContainer
	for _, c := range slices.Concat(pod.InitContainers, pod.Containers) {
		_, digest, _ := strings.Cut(c.Image, "@")
		command := c.Command
		switch {
		case len(command) > 0:
		case digest == c8sDigest:
			command = []string{secrets.InjectedBinary}
		default:
			command = []string{"/entrypoint"}
		}
		out = append(out, workloadclaims.SandboxContainer{
			Digest: digest,
			Argv:   slices.Concat(command, c.Args),
			Mounts: []pkgallowlist.ObservedMount{},
		})
	}
	return out
}

func match(seed *pkgallowlist.Allowlist, reported []workloadclaims.SandboxContainer) (string, error) {
	name, _, err := seed.MatchWorkload(secrets.WorkloadContainers(seed, reported))
	return name, err
}

// assertRouterMatches checks that the rendered router pod resolves to the
// seeded c8s-router entry and that the CDS, operator and mesh pods still
// resolve to their own single-image entries.
func assertRouterMatches(t *testing.T, out string) {
	t.Helper()
	seed := renderedSeed(t, out)
	if _, ok := seed.Workloads[routerEntry]; !ok {
		t.Fatalf("seed has no %s entry: %v", routerEntry, slices.Sorted(maps.Keys(seed.Workloads)))
	}
	for _, w := range renderedPodSpecs(t, out) {
		if !slices.Contains([]string{"c8s-router", "c8s-cds", "c8s-operator", "c8s-armtls-mesh"}, w.name) {
			continue
		}
		reported := running(w.spec)
		want := routerEntry
		if w.name != "c8s-router" {
			candidates := secrets.WorkloadContainers(seed, reported)
			if len(candidates) == 0 || candidates[0].Digest == "" {
				continue // an image pinned by tag has no entry to match
			}
			image := ""
			for _, c := range slices.Concat(w.spec.InitContainers, w.spec.Containers) {
				if strings.HasSuffix(c.Image, "@"+candidates[0].Digest) {
					image = c.Image
				}
			}
			digest, err := types.ParseDigest(candidates[0].Digest)
			if err != nil {
				t.Fatalf("%s: %v", w.name, err)
			}
			want = pkgallowlist.DigestEntryName(digest, image)
		}
		got, err := match(seed, reported)
		if err != nil || got != want {
			diff := seed.Workloads[want].Diff(secrets.WorkloadContainers(seed, reported))
			t.Errorf("MatchWorkload(%s %s) = %q, %v, want %q; foreign %+v, missing %+v", w.kind, w.name, got, err, want, diff.Foreign, diff.MissingMains)
		}
	}
}

func TestChartBakedRouterMatchesSeededEntry(t *testing.T) {
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertRouterMatches(t, out)

	pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	entry := renderedSeed(t, out).Workloads[routerEntry]
	if len(entry.InitContainers) != 1 || entry.InitContainers[0].Args.Argv[0] != "acme" {
		t.Errorf("acme must be declared as the entry's only init container, got %+v", entry.InitContainers)
	}
	if len(entry.Containers) != 3 {
		t.Errorf("entry mains = %d, want nginx, cds-attest and allowlist-proxy", len(entry.Containers))
	}

	seed := renderedSeed(t, out)
	reported := running(pod)
	for _, tc := range []struct {
		name   string
		want   string // "" wants ErrNoMatch
		mutate func([]workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer
	}{
		{
			name: "cds-attest with an extra flag",
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				for i, c := range cs {
					if len(c.Argv) > 1 && c.Argv[1] == "cds-attest" {
						cs[i].Argv = append(slices.Clone(c.Argv), "--verbose")
					}
				}
				return cs
			},
		},
		{
			name: "no allowlist-proxy",
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				return slices.DeleteFunc(cs, func(c workloadclaims.SandboxContainer) bool {
					return len(c.Argv) > 1 && c.Argv[1] == "allowlist-proxy"
				})
			},
		},
		{
			// A declared init is not required.
			name: "acme exited",
			want: routerEntry,
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				return slices.DeleteFunc(cs, func(c workloadclaims.SandboxContainer) bool {
					return len(c.Argv) > 1 && c.Argv[1] == "acme"
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := match(seed, tc.mutate(slices.Clone(reported)))
			if tc.want != "" {
				if err != nil || got != tc.want {
					t.Errorf("MatchWorkload = %q, %v, want %q", got, err, tc.want)
				}
				return
			}
			if !errors.Is(err, pkgallowlist.ErrNoMatch) {
				t.Errorf("MatchWorkload = %q, %v, want ErrNoMatch", got, err)
			}
		})
	}
}

func TestChartRouterEntryPresence(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "c8s image by tag", want: false},
		{name: "c8s image by digest", args: digestArgs, want: true},
		{name: "components not derived", args: []string{"--set", "image.digest=" + c8sDigest, "--set", "nriImagePolicy.policy.mode=audit"}, want: false},
		{name: "router disabled", args: append(slices.Clone(digestArgs), "--set", "router.enabled=false"), want: false},
		{
			// kubelet expands $(HOST_IP) in args, so the argv is node-specific.
			name: "attestation api by host IP",
			args: append(slices.Clone(digestArgs), "--set", "attestationApi.cvmMode=bare-metal", "--set", "attestationApi.enabled=false"),
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			if _, got := renderedSeed(t, out).Workloads[routerEntry]; got != tc.want {
				t.Fatalf("seed has %s = %v, want %v", routerEntry, got, tc.want)
			}
			if tc.want {
				assertRouterMatches(t, out)
			}
		})
	}
}
