package helmchart

import (
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// routerPrefix starts the seeded router entry's name; the rest hashes its content.
const routerPrefix = "c8s-router-"

// defaultGate stands for the seeded router entry's name in gate expectations.
const defaultGate = "<seeded entry>"

var c8sDigest = "sha256:" + strings.Repeat("1", 64)

var nginxByTag = []string{"--set-string", "router.nginx.image.digest=", "--set", "router.nginx.image.tag=1.30.5-alpine-slim"}

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

// routerEntryName returns the seeded router entry's name, or "" when none is seeded.
func routerEntryName(t *testing.T, seed *pkgallowlist.Allowlist) string {
	t.Helper()
	var names []string
	for name := range seed.Workloads {
		if strings.HasPrefix(name, routerPrefix) {
			names = append(names, name)
		}
	}
	switch len(names) {
	case 0:
		return ""
	case 1:
		if !regexp.MustCompile(`^c8s-router-[0-9a-f]{12}$`).MatchString(names[0]) {
			t.Fatalf("router entry name %q is not c8s-router-<12 hex>", names[0])
		}
		return names[0]
	default:
		t.Fatalf("seed has several router entries: %v", names)
		return ""
	}
}

func match(seed *pkgallowlist.Allowlist, reported []workloadclaims.SandboxContainer) (string, error) {
	name, _, err := seed.MatchWorkload(secrets.WorkloadContainers(seed, reported))
	return name, err
}

// assertRouterMatches checks that the rendered router pod resolves to the
// seeded router entry and that the CDS, operator and mesh pods still
// resolve to their own single-image entries.
func assertRouterMatches(t *testing.T, out string) {
	t.Helper()
	seed := renderedSeed(t, out)
	routerEntry := routerEntryName(t, seed)
	if routerEntry == "" {
		t.Fatalf("seed has no router entry: %v", slices.Sorted(maps.Keys(seed.Workloads)))
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
	seed := renderedSeed(t, out)
	routerEntry := routerEntryName(t, seed)
	entry := seed.Workloads[routerEntry]
	if len(entry.InitContainers) != 1 || entry.InitContainers[0].Args.Argv[0] != "acme" {
		t.Errorf("acme must be declared as the entry's only init container, got %+v", entry.InitContainers)
	}
	if len(entry.Containers) != 3 {
		t.Errorf("entry mains = %d, want nginx, cds-attest and allowlist-proxy", len(entry.Containers))
	}

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
		{name: "nginx by tag", args: append(slices.Clone(digestArgs), nginxByTag...), want: false},
		{name: "no c8s-image main", args: append(slices.Clone(digestArgs), "--set", "router.attest.enabled=false", "--set", "router.allowlist.enabled=false"), want: false},
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
			if got := routerEntryName(t, renderedSeed(t, out)) != ""; got != tc.want {
				t.Fatalf("router entry seeded = %v, want %v", got, tc.want)
			}
			if tc.want {
				assertRouterMatches(t, out)
			}
		})
	}
}

func TestChartRouterExpectedWorkloadDefault(t *testing.T) {
	noHostPort := []string{"--set", "router.hostPort.enabled=false"}
	for _, tc := range []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{name: "hostPort bound", args: digestArgs},
		{name: "entry seeded", args: slices.Concat(digestArgs, noHostPort), want: defaultGate},
		{name: "explicit name", args: slices.Concat(digestArgs, noHostPort, []string{"--set-string", "router.attest.expectedWorkload=infer"}), want: "infer"},
		{name: "explicit off", args: slices.Concat(digestArgs, noHostPort, []string{"--set-string", "router.attest.expectedWorkload="})},
		{name: "no entry", args: noHostPort},
		{name: "nginx by tag", args: slices.Concat(digestArgs, noHostPort, nginxByTag)},
		{name: "attest and allowlist disabled", args: slices.Concat(digestArgs, noHostPort, []string{"--set", "router.attest.enabled=false", "--set", "router.allowlist.enabled=false"})},
		// No inventory could stamp the leaf; the chart refuses the shape.
		{name: "no inventory", args: slices.Concat(digestArgs, noHostPort, []string{"--set", "nriImagePolicy.enabled=false", "--set", "attestationApi.cvmMode=gke"}), wantErr: "kind=require_host_image_policy"},
		{name: "baked", args: slices.Concat(bakedArgs, noHostPort, []string{"--set", "router.service.type=LoadBalancer"}), want: defaultGate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(out, tc.wantErr) {
					t.Fatalf("helm template: err = %v, want %q\n%s", err, tc.wantErr, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			var got string
			for _, c := range renderedDeployment(t, out, "c8s-router").Spec.Template.Spec.Containers {
				if c.Name == "cds-attest" {
					got = expectedWorkloadArg(c)
				}
			}
			want := tc.want
			if want == defaultGate {
				want = routerEntryName(t, renderedSeed(t, out))
			}
			if got != want || (tc.want == defaultGate && want == "") {
				t.Fatalf("--expected-workload = %q, want %q", got, want)
			}
			// get-cert holds out for the seeded entry whenever claims are wired, gate or not.
			cert, _ := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "c8s-cert")
			wantCert := ""
			if slices.Contains(cert.Args, "--workload-claims") {
				wantCert = routerEntryName(t, renderedSeed(t, out))
			}
			if got := expectedWorkloadArg(cert); got != wantCert {
				t.Errorf("c8s-cert --expected-workload = %q, want %q", got, wantCert)
			}
			if want == "" {
				return
			}
			assertRouterReadyzProbe(t, out)
			if tc.want == defaultGate {
				assertRouterMatches(t, out)
			}
		})
	}
}

// A changed digest or argv must seed a new entry: CDS skips a name it holds.
func TestChartRouterEntryNameTracksContent(t *testing.T) {
	name := func(args ...string) string {
		t.Helper()
		out, err := helmTemplate(t, slices.Concat(bakedArgs, args)...)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		return routerEntryName(t, renderedSeed(t, out))
	}
	base := name()
	if again := name(); again != base {
		t.Fatalf("router entry name is not stable: %q then %q", base, again)
	}
	for _, args := range [][]string{
		{"--set", "image.digest=sha256:" + strings.Repeat("3", 64)},
		{"--set", "router.nginx.image.digest=sha256:" + strings.Repeat("4", 64)},
		{"--set", "router.attest.port=8900"},
		{"--set", "router.hostPort.enabled=false", "--set", "router.service.type=LoadBalancer", "--set-string", "router.attest.expectedWorkload=infer"},
	} {
		if got := name(args...); got == base {
			t.Errorf("%v kept router entry name %q", args, got)
		}
	}
}

// gateArgs renders a router whose readiness gate can be on.
var gateArgs = slices.Concat(digestArgs, []string{"--set", "router.hostPort.enabled=false"})

func expectedWorkloadArg(c corev1.Container) string {
	for _, arg := range c.Args {
		if v, ok := strings.CutPrefix(arg, "--expected-workload="); ok {
			return v
		}
	}
	return ""
}

// Freezing the rendered default gate must keep the entry's name.
func TestChartRouterExplicitGateNamesSeededEntry(t *testing.T) {
	out, err := helmTemplate(t, gateArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	derived := routerEntryName(t, renderedSeed(t, out))

	out, err = helmTemplate(t, slices.Concat(gateArgs, []string{"--set-string", "router.attest.expectedWorkload=" + derived})...)
	if err != nil {
		t.Fatalf("helm template with expectedWorkload=%s: %v\n%s", derived, err, out)
	}
	if got := routerEntryName(t, renderedSeed(t, out)); got != derived {
		t.Errorf("explicit gate %q seeded entry %q", derived, got)
	}
	if got := expectedWorkloadArg(renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")); got != derived {
		t.Errorf("--expected-workload = %q, want %q", got, derived)
	}
	assertRouterMatches(t, out)

	stale := routerPrefix + strings.Repeat("0", 12)
	out, err = helmTemplate(t, slices.Concat(gateArgs, []string{"--set-string", "router.attest.expectedWorkload=" + stale})...)
	if err == nil || !strings.Contains(out, "does not name the seeded router entry") {
		t.Fatalf("expectedWorkload=%s: err = %v, want a render failure naming %s\n%s", stale, err, derived, out)
	}

	// Without a seeded entry a frozen name would hold the router unstamped.
	for _, tc := range []struct {
		name  string
		args  []string
		cause string
	}{
		{name: "nginx by tag", args: nginxByTag, cause: "router.nginx.image.digest is unset"},
		{name: "c8s image by tag", args: []string{"--set-string", "image.digest="}, cause: "image.digest is unset"},
		{name: "components not derived", args: []string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=false", "--set", "nriImagePolicy.policy.mode=audit"}, cause: "nriImagePolicy.bootstrapAllowlist.deriveComponents is false"},
		{name: "attestation api by host IP", args: []string{"--set", "attestationApi.cvmMode=bare-metal", "--set", "attestationApi.enabled=false"}, cause: "the router's argv holds a $ reference kubelet expands"},
		{name: "no c8s-image router container", args: []string{"--set", "router.attest.enabled=false", "--set", "router.allowlist.enabled=false"}, cause: "no router container runs the c8s image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, slices.Concat(gateArgs, tc.args, []string{"--set-string", "router.attest.expectedWorkload=" + derived})...)
			if err == nil || !strings.Contains(out, "seed none because "+tc.cause) {
				t.Fatalf("expectedWorkload=%s: err = %v, want a render failure naming %q\n%s", derived, err, tc.cause, out)
			}
		})
	}
}

func TestChartRouterOperatorEntry(t *testing.T) {
	nginxDigest := "sha256:" + strings.Repeat("5", 64)
	container := func(digest string) string {
		return `{"digest":"` + digest + `","image":"r@` + digest + `","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}`
	}
	workload := func(name string, digests ...string) []string {
		var cs []string
		for _, d := range digests {
			cs = append(cs, container(d))
		}
		return []string{"--set-json", `nriImagePolicy.bootstrapAllowlist.workloads.` + name + `={"label":"mine","initContainers":[],"containers":[` + strings.Join(cs, ",") + `]}`}
	}
	entry := slices.Concat([]string{"--set", "router.nginx.image.digest=" + nginxDigest}, workload("my-router", nginxDigest, c8sDigest))
	gate := func(name string) []string { return []string{"--set-string", "router.attest.expectedWorkload=" + name} }

	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "beside the seeded entry", args: entry, wantErr: "would match each of c8s-router-"},
		{name: "two operator entries", args: slices.Concat(entry, workload("other-router", nginxDigest, c8sDigest), gate("my-router")), wantErr: "would match each of my-router, other-router"},
		{name: "two nginx-only entries without a c8s-image router container", args: slices.Concat(entry[:2], workload("my-router", nginxDigest), workload("other-router", nginxDigest), []string{"--set", "router.attest.enabled=false", "--set", "router.allowlist.enabled=false"}), wantErr: "would match each of my-router, other-router"},
		{name: "init container of a third image", args: slices.Concat(entry[:2], []string{"--set-json", `nriImagePolicy.bootstrapAllowlist.workloads.my-router={"label":"mine","initContainers":[` + container("sha256:"+strings.Repeat("6", 64)) + `],"containers":[` + container(nginxDigest) + `,` + container(c8sDigest) + `]}`}), wantErr: "would match each of c8s-router-"},
		{name: "gate on an entry without nginx", args: slices.Concat(entry[:2], workload("c8s-only", c8sDigest), gate("c8s-only")), wantErr: "router.attest.expectedWorkload=c8s-only names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, slices.Concat(gateArgs, tc.args)...)
			if err == nil || !strings.Contains(out, tc.wantErr) {
				t.Fatalf("helm template: err = %v, want %q\n%s", err, tc.wantErr, out)
			}
		})
	}

	out, err := helmTemplate(t, slices.Concat(gateArgs, entry, gate("my-router"))...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	if got := routerEntryName(t, seed); got != "" {
		t.Errorf("gate naming an operator entry still seeded %q", got)
	}
	if _, ok := seed.Workloads["my-router"]; !ok {
		t.Errorf("seed lost the operator entry: %v", slices.Sorted(maps.Keys(seed.Workloads)))
	}
	if got := expectedWorkloadArg(renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")); got != "my-router" {
		t.Errorf("--expected-workload = %q, want my-router", got)
	}
	if got := certExpectedWorkload(t, out); got != "my-router" {
		t.Errorf("c8s-cert --expected-workload = %q, want my-router", got)
	}

	// pinnedWorkload lists nginx and one c8s-image container per argv, its args pinned to it.
	pinnedWorkload := func(name string, argvs ...[]string) []string {
		t.Helper()
		cs := []string{container(nginxDigest)}
		for _, argv := range argvs {
			pinned, err := json.Marshal(map[string]any{
				"digest": c8sDigest, "image": "r@" + c8sDigest,
				"command": map[string]any{"policy": "exact", "argv": []string{secrets.InjectedBinary}},
				"args":    map[string]any{"policy": "exact", "argv": argv},
				"mounts":  map[string]any{"policy": "any"},
			})
			if err != nil {
				t.Fatal(err)
			}
			cs = append(cs, string(pinned))
		}
		return []string{"--set-json", `nriImagePolicy.bootstrapAllowlist.workloads.` + name + `={"label":"mine","initContainers":[],"containers":[` + strings.Join(cs, ",") + `]}`}
	}
	// routerArgs returns the cds-attest and allowlist-proxy args the router renders.
	routerArgs := func(args ...string) ([]string, []string) {
		t.Helper()
		out, err := helmTemplate(t, slices.Concat(gateArgs, entry[:2], args)...)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		return renderedDeploymentContainer(t, out, "c8s-router", "cds-attest").Args, renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy").Args
	}

	// Both router images, but an argv pin the router never runs: not a router entry.
	foreign := pinnedWorkload("my-server", []string{"serve", "--port=9000"})
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], foreign)...)
	if err != nil {
		t.Fatalf("helm template with a pinned two-image operator entry: %v\n%s", err, out)
	}
	if _, ok := renderedSeed(t, out).Workloads["my-server"]; !ok {
		t.Errorf("seed lost the pinned operator entry")
	}
	assertRouterMatches(t, out)
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], foreign, gate("my-server"))...)
	if err == nil || !strings.Contains(out, "names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match") {
		t.Fatalf("gate on the pinned entry: err = %v, want a cannot-match failure\n%s", err, out)
	}

	// Pinning every argv the router runs keeps it a router entry, gated or not.
	cdsAttest, allowlistProxy := routerArgs(gate("my-router")...)
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], pinnedWorkload("my-router", cdsAttest), gate("my-router"))...)
	if err == nil || !strings.Contains(out, "names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match") {
		t.Fatalf("gate on an entry missing allowlist-proxy: err = %v, want a cannot-match failure\n%s", err, out)
	}
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], pinnedWorkload("my-router", cdsAttest, allowlistProxy), gate("my-router"))...)
	if err != nil {
		t.Fatalf("helm template with a pinned router entry: %v\n%s", err, out)
	}
	seed = renderedSeed(t, out)
	if got := routerEntryName(t, seed); got != "" {
		t.Errorf("gate naming a pinned operator entry still seeded %q", got)
	}
	if got, err := match(seed, running(renderedDeployment(t, out, "c8s-router").Spec.Template.Spec)); err != nil || got != "my-router" {
		t.Errorf("MatchWorkload(router) = %q, %v, want my-router", got, err)
	}
	// narrowed swaps the c8s-image containers' mounts policy for policies.
	narrowed := func(workload []string, policies string) []string {
		out := slices.Clone(workload)
		out[1] = strings.ReplaceAll(out[1], `"image":"r@`+c8sDigest+`","mounts":{"policy":"any"}`, `"image":"r@`+c8sDigest+`"`+policies)
		return out
	}
	// A gate needs an entry proven to admit the router's mounts and env.
	for _, policies := range []string{"", `,"mounts":{"policy":"any"},"env":{"policy":"deny"}`} {
		out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], narrowed(pinnedWorkload("my-router", cdsAttest, allowlistProxy), policies), gate("my-router"))...)
		if err == nil || !strings.Contains(out, "names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match") {
			t.Fatalf("gate on an entry with policies %q: err = %v, want a cannot-match failure\n%s", policies, err, out)
		}
	}

	// An operator entry may itself carry a c8s-router- name.
	cdsAttest, allowlistProxy = routerArgs(gate("my-router")...)
	cdsAttest = slices.Clone(cdsAttest)
	cdsAttest[slices.Index(cdsAttest, "--expected-workload=my-router")] = "--expected-workload=c8s-router-custom"
	custom := pinnedWorkload("c8s-router-custom", cdsAttest, allowlistProxy)
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], custom, gate("c8s-router-custom"))...)
	if err != nil {
		t.Fatalf("helm template gated on c8s-router-custom: %v\n%s", err, out)
	}
	seed = renderedSeed(t, out)
	if got, err := match(seed, running(renderedDeployment(t, out, "c8s-router").Spec.Template.Spec)); err != nil || got != "c8s-router-custom" {
		t.Errorf("MatchWorkload(router) = %q, %v, want c8s-router-custom", got, err)
	}
	if got := expectedWorkloadArg(renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")); got != "c8s-router-custom" {
		t.Errorf("--expected-workload = %q, want c8s-router-custom", got)
	}
	bareMetal := []string{"--set", "attestationApi.cvmMode=bare-metal", "--set", "attestationApi.enabled=false"}
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], narrowed(custom, ""), gate("c8s-router-custom"), bareMetal)...)
	if err == nil || !strings.Contains(out, "names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match") {
		t.Fatalf("gate on an unmatchable c8s-router-custom: err = %v, want a cannot-match failure\n%s", err, out)
	}

	// With nginx by tag the chart cannot judge the entry and takes the gate as written.
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], custom, gate("c8s-router-custom"), nginxByTag)...)
	if err != nil {
		t.Fatalf("helm template gated on c8s-router-custom with nginx by tag: %v\n%s", err, out)
	}
	if got := expectedWorkloadArg(renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")); got != "c8s-router-custom" {
		t.Errorf("--expected-workload = %q, want c8s-router-custom", got)
	}

	// nginx declared without policies is deny, which its argv never meets.
	cdsAttest, allowlistProxy = routerArgs(gate("my-router")...)
	bareNginx := pinnedWorkload("my-router", cdsAttest, allowlistProxy)
	bareNginx[1] = strings.Replace(bareNginx[1], container(nginxDigest), `{"digest":"`+nginxDigest+`","image":"r@`+nginxDigest+`","mounts":{"policy":"any"}}`, 1)
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], bareNginx, gate("my-router"))...)
	if err == nil || !strings.Contains(out, "names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match") {
		t.Fatalf("gate on an entry with a policy-less nginx: err = %v, want a cannot-match failure\n%s", err, out)
	}

	cdsAttest, allowlistProxy = routerArgs()
	for _, policies := range []string{`,"mounts":{"policy":"any"}`, `,"mounts":{"policy":"exact","rules":[{"destination":"/tls","kind":"emptyDir"}]}`} {
		out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], narrowed(pinnedWorkload("my-router", cdsAttest, allowlistProxy), policies))...)
		if err == nil || !strings.Contains(out, "would match each of c8s-router-") {
			t.Fatalf("pinned router entry with policies %q beside the seeded one: err = %v, want a collision failure\n%s", policies, err, out)
		}
	}

	// kubelet expands $(HOST_IP), so a pin on the unexpanded argv is not proven.
	cdsAttest, allowlistProxy = routerArgs(slices.Concat(bareMetal, gate("my-router"))...)
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], bareMetal, pinnedWorkload("my-router", cdsAttest, allowlistProxy), gate("my-router"))...)
	if err == nil || !strings.Contains(out, "names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match") {
		t.Fatalf("gate on an entry pinning expanded argv: err = %v, want a cannot-match failure\n%s", err, out)
	}

	// Without an any-argv c8s-image entry get-cert is not dropped, so the router matches nothing.
	notDerived := []string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=false", "--set", "nriImagePolicy.policy.mode=audit"}
	cdsAttest, allowlistProxy = routerArgs(slices.Concat(notDerived, gate("my-router"))...)
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], notDerived, pinnedWorkload("my-router", cdsAttest, allowlistProxy), gate("my-router"))...)
	if err == nil || !strings.Contains(out, "get-cert must also be droppable as injected") {
		t.Fatalf("gate without deriveComponents: err = %v, want a cannot-match failure\n%s", err, out)
	}
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], notDerived, workload("my-router", nginxDigest, c8sDigest), gate("my-router"))...)
	if err != nil {
		t.Fatalf("helm template with an any-argv router entry without deriveComponents: %v\n%s", err, out)
	}
	if got, err := match(renderedSeed(t, out), running(renderedDeployment(t, out, "c8s-router").Spec.Template.Spec)); err != nil || got != "my-router" {
		t.Errorf("MatchWorkload(router without deriveComponents) = %q, %v, want my-router", got, err)
	}

	// A command pin over expanded argv may match too.
	cdsAttest, allowlistProxy = routerArgs(bareMetal...)
	commandPinned := func(name string) []string {
		t.Helper()
		cs := []string{container(nginxDigest)}
		for _, args := range [][]string{cdsAttest, allowlistProxy} {
			pinned, err := json.Marshal(map[string]any{
				"digest": c8sDigest, "image": "r@" + c8sDigest,
				"command": map[string]any{"policy": "exact", "argv": slices.Concat([]string{secrets.InjectedBinary}, args)},
				"args":    map[string]any{"policy": "deny"},
				"mounts":  map[string]any{"policy": "any"},
			})
			if err != nil {
				t.Fatal(err)
			}
			cs = append(cs, string(pinned))
		}
		return []string{"--set-json", `nriImagePolicy.bootstrapAllowlist.workloads.` + name + `={"label":"mine","initContainers":[],"containers":[` + strings.Join(cs, ",") + `]}`}
	}
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], bareMetal, commandPinned("router-a"), commandPinned("router-b"))...)
	if err == nil || !strings.Contains(out, "would match each of router-a, router-b") {
		t.Fatalf("two command-pinned router entries on bare metal: err = %v, want a collision failure\n%s", err, out)
	}

	// Expanded argv still rules out pins of another length or other args.
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], bareMetal, pinnedWorkload("server-a", []string{"serve", "--port=9000"}), pinnedWorkload("server-b", []string{"serve", "--port=9001"}))...)
	if err != nil {
		t.Fatalf("helm template with unrelated pinned entries on bare metal: %v\n%s", err, out)
	}

	// acme runs as a native sidecar, which an entry admits as an init container.
	acmeArgs := []string{
		"--set-string", "router.publicTLS.mode=acme",
		"--set", "router.san={lb.example.com}",
		"--set-string", "router.acme.email=ops@example.com",
		"--set", "router.service.type=LoadBalancer",
	}
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], acmeArgs, gate("my-router"))...)
	if err != nil {
		t.Fatalf("helm template with acme: %v\n%s", err, out)
	}
	cdsAttest = renderedDeploymentContainer(t, out, "c8s-router", "cds-attest").Args
	allowlistProxy = renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy").Args
	acme, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "acme")
	if !ok {
		t.Fatal("acme init container missing")
	}
	withAcme := pinnedWorkload("my-router", cdsAttest, allowlistProxy)
	acmeInit, err := json.Marshal(map[string]any{
		"digest": c8sDigest, "image": "r@" + c8sDigest,
		"command": map[string]any{"policy": "exact", "argv": []string{secrets.InjectedBinary}},
		"args":    map[string]any{"policy": "exact", "argv": acme.Args},
		"mounts":  map[string]any{"policy": "any"},
	})
	if err != nil {
		t.Fatal(err)
	}
	withAcme[1] = strings.Replace(withAcme[1], `"initContainers":[]`, `"initContainers":[`+string(acmeInit)+`]`, 1)
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], acmeArgs, withAcme, gate("my-router"))...)
	if err != nil {
		t.Fatalf("helm template with an acme-admitting router entry: %v\n%s", err, out)
	}
	if got, err := match(renderedSeed(t, out), running(renderedDeployment(t, out, "c8s-router").Spec.Template.Spec)); err != nil || got != "my-router" {
		t.Errorf("MatchWorkload(router with acme) = %q, %v, want my-router", got, err)
	}
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry[:2], acmeArgs, pinnedWorkload("my-router", cdsAttest, allowlistProxy), gate("my-router"))...)
	if err == nil || !strings.Contains(out, "names a nriImagePolicy.bootstrapAllowlist.workloads entry the router pod cannot match") {
		t.Fatalf("gate on an entry not admitting acme: err = %v, want a cannot-match failure\n%s", err, out)
	}

	// An operator entry holding one router image cannot match the router pod.
	out, err = helmTemplate(t, slices.Concat(gateArgs, entry, workload("c8s-only", c8sDigest), gate("my-router"))...)
	if err != nil {
		t.Fatalf("helm template with a c8s-only operator entry: %v\n%s", err, out)
	}
	if got := routerEntryName(t, renderedSeed(t, out)); got != "" {
		t.Errorf("gate naming an operator entry still seeded %q", got)
	}
	if got := certExpectedWorkload(t, out); got != "my-router" {
		t.Errorf("c8s-cert --expected-workload = %q, want my-router", got)
	}
}

func certExpectedWorkload(t *testing.T, out string) string {
	t.Helper()
	cert, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "c8s-cert")
	if !ok {
		t.Fatal("c8s-cert init container missing")
	}
	return expectedWorkloadArg(cert)
}

// The schema rejects the type before rendering; router.expectedWorkload
// repeats the check for renders that skip schema validation.
func TestChartRouterExpectedWorkloadType(t *testing.T) {
	out, err := helmTemplate(t, slices.Concat(gateArgs, []string{"--set", "router.attest.expectedWorkload=true"})...)
	// Helm's schema error wording changes across releases.
	if err == nil || !strings.Contains(out, "don't meet the specifications of the schema") || !strings.Contains(out, "expectedWorkload") {
		t.Fatalf("boolean expectedWorkload: err = %v, want the schema's type error\n%s", err, out)
	}
}
