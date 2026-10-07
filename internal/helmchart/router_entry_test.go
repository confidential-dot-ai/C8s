package helmchart

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// routerPrefix starts the seeded router entry's name; the rest hashes its content.
const routerPrefix = "c8s-router-"

// defaultGate stands for the seeded router entry's name in gate expectations.
const defaultGate = "<seeded entry>"

var c8sDigest = "sha256:" + strings.Repeat("1", 64)

var nginxByTag = []string{"--set-string", "router.nginx.image.digest=", "--set", "router.nginx.image.tag=1.30.5-alpine-slim"}

// digestArgs pins the c8s image outside the baked shape. deriveComponents
// derives its pin.
var digestArgs = []string{
	"--set", "image.digest=" + c8sDigest,
	"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
}

// nginxEntrypoint and nginxCmd are router.nginx.image's ENTRYPOINT and CMD.
var (
	nginxEntrypoint = []string{"/docker-entrypoint.sh"}
	nginxCmd        = []string{"nginx", "-g", "daemon off;"}
)

// running is the set the node inventory reports for a rendered pod: a pod
// command replaces the entrypoint, which is /c8s for the c8s image, the
// image's own for nginx, and the one the seed pins for the other component
// images. The argv is the kubelet's expansion, the env the launch
// environment (launchEnv), and the mounts are what the node observes.
func running(t *testing.T, seed *pkgallowlist.Allowlist, pod corev1.PodSpec) []workloadclaims.SandboxContainer {
	t.Helper()
	envs := componentImageEnvValues(t)
	var out []workloadclaims.SandboxContainer
	for _, c := range slices.Concat(pod.InitContainers, pod.Containers) {
		_, digest, _ := strings.Cut(c.Image, "@")
		imageEnv := envs["image"]
		if strings.Contains(c.Image, "nginx-unprivileged@") {
			imageEnv = envs["router.nginx"]
		}
		command, args := c.Command, c.Args
		switch {
		case len(command) > 0:
		case digest == c8sDigest:
			command = []string{secrets.InjectedBinary}
		case strings.Contains(c.Image, "nginx-unprivileged@"):
			command = nginxEntrypoint
			if len(args) == 0 {
				args = nginxCmd
			}
		default:
			command = seededEntrypoint(seed, digest)
		}
		c.Command, c.Args = command, args
		out = append(out, workloadclaims.SandboxContainer{
			Digest: digest,
			Argv:   runtimeArgv(c, nil),
			Mounts: observedMounts(t, pod, c),
			Env:    launchEnv(t, pod, c, imageEnv),
		})
	}
	return out
}

// seededEntrypoint is the command the seed pins digest to, or /entrypoint when
// it pins none.
func seededEntrypoint(seed *pkgallowlist.Allowlist, digest string) []string {
	for _, name := range slices.Sorted(maps.Keys(seed.Workloads)) {
		w := seed.Workloads[name]
		for _, c := range slices.Concat(w.InitContainers, w.Containers) {
			if c.Digest.String() == digest && c.Command.Policy == pkgallowlist.PolicyExact {
				return c.Command.Argv
			}
		}
	}
	return []string{"/entrypoint"}
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
// seeded router entry. The other component pods run their own c8s-cert
// sidecars, pinned to exact args, so they are declared containers rather than
// injected ones and no single-image entry describes those pods.
func assertRouterMatches(t *testing.T, out string) {
	t.Helper()
	seed := renderedSeed(t, out)
	routerEntry := routerEntryName(t, seed)
	if routerEntry == "" {
		t.Fatalf("seed has no router entry: %v", slices.Sorted(maps.Keys(seed.Workloads)))
	}
	reported := running(t, seed, renderedDeployment(t, out, "c8s-router").Spec.Template.Spec)
	got, err := match(seed, reported)
	if err != nil || got != routerEntry {
		diff := seed.Workloads[routerEntry].Diff(secrets.WorkloadContainers(seed, reported))
		t.Errorf("MatchWorkload(router) = %q, %v, want %q; foreign %+v, missing %+v", got, err, routerEntry, diff.Foreign, diff.MissingMains)
	}
}

func TestChartBakedRouterMatchesSeededEntry(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertRouterMatches(t, out)

	pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	seed := renderedSeed(t, out)
	routerEntry := routerEntryName(t, seed)
	entry := seed.Workloads[routerEntry]
	if len(entry.Containers) != 3 {
		t.Errorf("entry mains = %+v, want nginx, cds-attest and allowlist-proxy", entry.Containers)
	}
	var inits []string
	for _, c := range entry.InitContainers {
		if c.Mounts.Policy != pkgallowlist.PolicyExact || c.Args.Policy != pkgallowlist.PolicyExact {
			t.Errorf("init %v leaves args %q or mounts %q open", c.Args.Argv, c.Args.Policy, c.Mounts.Policy)
		}
		if mode := c.Args.Argv[0]; !slices.Contains(inits, mode) {
			inits = append(inits, mode)
		}
	}
	slices.Sort(inits)
	if want := []string{"acme", "get-cert", "probe-file"}; !slices.Equal(inits, want) {
		t.Errorf("entry init modes = %v, want %v", inits, want)
	}

	reported := running(t, seed, pod)
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
			name: "no cds-attest",
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				return slices.DeleteFunc(cs, func(c workloadclaims.SandboxContainer) bool {
					return len(c.Argv) > 1 && c.Argv[1] == "cds-attest"
				})
			},
		},
		{
			name: "no nginx",
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				return slices.DeleteFunc(cs, func(c workloadclaims.SandboxContainer) bool {
					return c.Digest != c8sDigest
				})
			},
		},
		{
			name: "cds-attest with an extra mount",
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				for i, c := range cs {
					if len(c.Argv) > 1 && c.Argv[1] == "cds-attest" {
						cs[i].Mounts = append(slices.Clone(c.Mounts), pkgallowlist.ObservedMount{Destination: "/extra", Class: pkgallowlist.MountEmptyDir, Storage: pkgallowlist.MountMemory})
					}
				}
				return cs
			},
		},
		{
			name: "allowlist-proxy socket from another host source",
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				other, err := pkgallowlist.HostSourceDigest("/var/run/nri-image-policy")
				if err != nil {
					t.Fatal(err)
				}
				for i, c := range cs {
					if len(c.Argv) > 1 && c.Argv[1] == "allowlist-proxy" {
						cs[i].Mounts = slices.Clone(c.Mounts)
						for j, m := range cs[i].Mounts {
							if m.Class == pkgallowlist.MountHost {
								cs[i].Mounts[j].HostSourceDigest = other
							}
						}
					}
				}
				return cs
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
	t.Parallel()
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
		// cds-attest runs for application routing even with its attestation endpoints off.
		{name: "attest and allowlist disabled", args: append(slices.Clone(digestArgs), "--set", "router.attest.enabled=false", "--set", "router.allowlist.enabled=false"), want: true},
		{
			// The argv carries $(HOST_IP) literally; the binary expands it.
			name: "attestation api by host IP",
			args: append(slices.Clone(digestArgs), "--set", "attestationApi.cvmMode=bare-metal", "--set", "attestationApi.enabled=false", "--set", "nriImagePolicy.policy.mode=audit"),
			want: true,
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
	t.Parallel()
	noHostPort := []string{"--set", "router.hostPort.enabled=false"}
	for _, tc := range []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{name: "hostPort bound", args: digestArgs},
		{name: "entry seeded", args: slices.Concat(digestArgs, noHostPort), want: defaultGate},
		{name: "explicit off", args: slices.Concat(digestArgs, noHostPort, []string{"--set-string", "router.attest.expectedWorkload="})},
		{name: "no entry", args: noHostPort},
		{name: "nginx by tag", args: slices.Concat(digestArgs, noHostPort, nginxByTag)},
		{name: "attest and allowlist disabled", args: slices.Concat(digestArgs, noHostPort, []string{"--set", "router.attest.enabled=false", "--set", "router.allowlist.enabled=false"}), want: defaultGate},
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
			if !slices.Contains(cert.Args, "--no-workload-claims") {
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
	t.Parallel()
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
		// The default gate adds --expected-workload to cds-attest.
		{"--set", "router.hostPort.enabled=false", "--set", "router.service.type=LoadBalancer"},
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
	t.Parallel()
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, slices.Concat(gateArgs, tc.args, []string{"--set-string", "router.attest.expectedWorkload=" + derived})...)
			if err == nil || !strings.Contains(out, "seed none because "+tc.cause) {
				t.Fatalf("expectedWorkload=%s: err = %v, want a render failure naming %q\n%s", derived, err, tc.cause, out)
			}
		})
	}
}

// A gate naming another entry is the operator's own router entry: the chart
// seeds none and passes the name through unchecked.
func TestChartRouterOperatorGate(t *testing.T) {
	t.Parallel()
	nginxDigest := "sha256:" + strings.Repeat("5", 64)
	var containers []string
	for _, digest := range []string{nginxDigest, c8sDigest} {
		containers = append(containers, `{"digest":"`+digest+`","image":"r@`+digest+`","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}`)
	}
	entry := []string{
		"--set", "router.nginx.image.digest=" + nginxDigest,
		"--set-json", `nriImagePolicy.bootstrapAllowlist.workloads.my-router={"label":"mine","initContainers":[],"containers":[` + strings.Join(containers, ",") + `]}`,
	}
	routerMatch := func(out string) (string, error) {
		seed := renderedSeed(t, out)
		return match(seed, running(t, seed, renderedDeployment(t, out, "c8s-router").Spec.Template.Spec))
	}

	// Ungated, the entry sits beside the seeded one and the router leaf goes unnamed.
	out, err := helmTemplate(t, slices.Concat(gateArgs, entry)...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got, err := routerMatch(out); !errors.Is(err, pkgallowlist.ErrAmbiguous) {
		t.Errorf("MatchWorkload(router) = %q, %v, want ErrAmbiguous", got, err)
	}

	out, err = helmTemplate(t, slices.Concat(gateArgs, entry, []string{"--set-string", "router.attest.expectedWorkload=my-router"})...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := routerEntryName(t, renderedSeed(t, out)); got != "" {
		t.Errorf("operator gate still seeded %q", got)
	}
	if got, err := routerMatch(out); err != nil || got != "my-router" {
		t.Errorf("MatchWorkload(router) = %q, %v, want my-router", got, err)
	}
	if got := expectedWorkloadArg(renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")); got != "my-router" {
		t.Errorf("cds-attest --expected-workload = %q, want my-router", got)
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
	t.Parallel()
	out, err := helmTemplate(t, slices.Concat(gateArgs, []string{"--set", "router.attest.expectedWorkload=true"})...)
	// Helm's schema error wording changes across releases; the template's
	// own message would mean the schema let the value through.
	if err == nil || !strings.Contains(out, "expectedWorkload") || strings.Contains(out, "must be a string or null") {
		t.Fatalf("boolean expectedWorkload: err = %v, want the schema's type error\n%s", err, out)
	}

	// A chart copy without its schema reaches the template's check.
	dir := t.TempDir()
	if err := os.CopyFS(filepath.Join(dir, "c8s"), os.DirFS("c8s")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "c8s", "values.schema.json")); err != nil {
		t.Fatal(err)
	}
	out, err = helmTemplateIn(t, dir, slices.Concat(gateArgs, []string{"--set", "router.attest.expectedWorkload=true"})...)
	if err == nil || !strings.Contains(out, "must be a string or null") {
		t.Fatalf("boolean expectedWorkload without schema validation: err = %v, want the template's type error\n%s", err, out)
	}
}

// cds-attest reads the measured-policy journal from the runtime directory it
// mounts beside the attestation-api socket, and only when it serves the
// attestation bundles that carry the list.
func TestChartCDSAttestMeasuredPoliciesFile(t *testing.T) {
	const dir = "/run/custom-nri"
	for _, tc := range []struct {
		name     string
		args     []string
		wantFlag bool
	}{
		{name: "no attestation-api", args: []string{"--set", "attestationApi.enabled=false"}},
		{name: "attestation-api", args: []string{"--set", "attestationApi.enabled=true"}, wantFlag: true},
		{name: "baked", args: bakedArgs, wantFlag: true},
		{name: "attest endpoints off", args: []string{"--set", "attestationApi.enabled=true", "--set", "router.attest.enabled=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, append(slices.Clone(tc.args), "--set-string", "nriImagePolicy.hostPaths.runtimeDir="+dir)...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
			flag := "--measured-policies-file=" + dir + "/measured-policies"
			if got := slices.Contains(attest.Args, flag); got != tc.wantFlag {
				t.Fatalf("cds-attest carries %s: %v, want %v\nargs: %v", flag, got, tc.wantFlag, attest.Args)
			}
			mounted := slices.ContainsFunc(attest.VolumeMounts, func(m corev1.VolumeMount) bool {
				return m.MountPath == dir && m.ReadOnly
			})
			if tc.wantFlag && !mounted {
				t.Errorf("cds-attest reads the journal without mounting %s read-only: %+v", dir, attest.VolumeMounts)
			}
		})
	}
}

// The mesh reads the journal from the runtime directory it mounts for the
// attestation-api socket, wherever cds-attest does.
func TestChartMeshMeasuredPoliciesFile(t *testing.T) {
	const dir = "/run/custom-nri"
	for _, tc := range []struct {
		name     string
		args     []string
		wantFlag bool
	}{
		{name: "no attestation-api", args: []string{"--set", "attestationApi.enabled=false"}},
		{name: "attestation-api", args: []string{"--set", "attestationApi.enabled=true"}, wantFlag: true},
		{name: "baked", args: bakedArgs, wantFlag: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, append(slices.Clone(tc.args), "--set-string", "nriImagePolicy.hostPaths.runtimeDir="+dir)...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			mesh := renderedDaemonSetContainer(t, out, "c8s-armtls-mesh", "armtls-mesh")
			flag := "--measured-policies-file=" + dir + "/measured-policies"
			if got := slices.Contains(mesh.Args, flag); got != tc.wantFlag {
				t.Fatalf("armtls-mesh carries %s: %v, want %v\nargs: %v", flag, got, tc.wantFlag, mesh.Args)
			}
			mounted := slices.ContainsFunc(mesh.VolumeMounts, func(m corev1.VolumeMount) bool {
				return m.MountPath == dir && m.ReadOnly
			})
			if tc.wantFlag && !mounted {
				t.Errorf("armtls-mesh reads the journal without mounting %s read-only: %+v", dir, mesh.VolumeMounts)
			}
		})
	}
}

// CDS reads the journal from the runtime directory it mounts for the
// attestation-api socket, wherever the mesh does.
func TestChartCDSMeasuredPoliciesFile(t *testing.T) {
	const dir = "/run/custom-nri"
	for _, tc := range []struct {
		name     string
		args     []string
		wantFlag bool
	}{
		{name: "no attestation-api", args: []string{"--set", "attestationApi.enabled=false"}},
		{name: "attestation-api", args: []string{"--set", "attestationApi.enabled=true"}, wantFlag: true},
		{name: "baked", args: bakedArgs, wantFlag: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, append(slices.Clone(tc.args), "--set-string", "nriImagePolicy.hostPaths.runtimeDir="+dir)...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
			flag := "--measured-policies-file=" + dir + "/measured-policies"
			if got := slices.Contains(cds.Args, flag); got != tc.wantFlag {
				t.Fatalf("cds carries %s: %v, want %v\nargs: %v", flag, got, tc.wantFlag, cds.Args)
			}
			mounted := slices.ContainsFunc(cds.VolumeMounts, func(m corev1.VolumeMount) bool {
				return m.MountPath == dir && m.ReadOnly
			})
			if tc.wantFlag && !mounted {
				t.Errorf("cds reads the journal without mounting %s read-only: %+v", dir, cds.VolumeMounts)
			}
		})
	}
}

// The chart's default runtime directory is where the node's binaries look for
// the journal, so the two never drift apart.
func TestChartDefaultMeasuredPoliciesFileIsNodeJournal(t *testing.T) {
	out, err := helmTemplate(t, "--set", "attestationApi.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	if flag := "--measured-policies-file=" + armtls.NodeJournal; !slices.Contains(attest.Args, flag) {
		t.Fatalf("cds-attest args lack %s: %v", flag, attest.Args)
	}
}
