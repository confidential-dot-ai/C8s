package helmchart

import (
	"errors"
	"maps"
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

var c8sDigest = "sha256:" + strings.Repeat("1", 64)

// digestArgs pins the c8s image outside the baked shape. deriveComponents
// derives its pin.
var digestArgs = []string{
	"--set", "image.digest=" + c8sDigest,
}

// The router's nginx image is pinned in c8s-lib's components file, so the
// chart's values carry no image object for a release to retag or repin.
func TestChartRouterNginxImageIsNotAValue(t *testing.T) {
	t.Parallel()
	for _, pin := range []string{
		"router.nginx.image.digest=sha256:" + strings.Repeat("4", 64),
		"router.nginx.image.tag=1.30.6-alpine-slim",
	} {
		out, err := helmTemplate(t, "--set-string", pin)
		if err == nil {
			t.Fatalf("--set-string %s rendered; the schema must refuse it\n%s", pin, out)
		}
		if !strings.Contains(out, "schema") || !strings.Contains(out, "image") {
			t.Fatalf("--set-string %s was refused without naming the schema and the key:\n%s", pin, out)
		}
	}
}

// nginxEntrypoint and nginxCmd are the router nginx image's ENTRYPOINT and CMD.
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
			imageEnv = envs["routerNginx"]
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
			// The role the node's base grants this launch, which is what the
			// drop set reads (routerPodRoles).
			Role: routerPodRoles[c.Name],
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
	name, _, err := seed.MatchWorkload(secrets.WorkloadContainers(reported))
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
		diff := seed.Workloads[routerEntry].Diff(secrets.WorkloadContainers(reported))
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
	// The allowlist proxy holds the credentials role, so the drop set removes
	// it before matching and the entry declares it no more than the mesh
	// endpoint or the credential sidecars.
	if len(entry.Containers) != 2 {
		t.Errorf("entry mains = %+v, want nginx and cds-attest", entry.Containers)
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
	if want := []string{"acme"}; !slices.Equal(inits, want) {
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
			name: "nginx configuration from another host source",
			mutate: func(cs []workloadclaims.SandboxContainer) []workloadclaims.SandboxContainer {
				other, err := pkgallowlist.HostSourceDigest("/var/run/nri-image-policy")
				if err != nil {
					t.Fatal(err)
				}
				for i, c := range cs {
					if c.Digest == c8sDigest {
						continue
					}
					cs[i].Mounts = slices.Clone(c.Mounts)
					for j, m := range cs[i].Mounts {
						if m.Class == pkgallowlist.MountHost {
							cs[i].Mounts[j].HostSourceDigest = other
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
		{"--set", "router.attest.port=8900"},
	} {
		if got := name(args...); got == base {
			t.Errorf("%v kept router entry name %q", args, got)
		}
	}
}

func expectedWorkloadArg(c corev1.Container) string {
	for _, arg := range c.Args {
		if v, ok := strings.CutPrefix(arg, "--expected-workload="); ok {
			return v
		}
	}
	return ""
}

// cds-attest reads the measured-policy journal from the runtime directory it
// mounts beside the attestation-api socket.
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

// publishedHostPorts are a rendered pod's host ports, as an entry declares them.
func publishedHostPorts(pod corev1.PodSpec) []pkgallowlist.HostPort {
	var out []pkgallowlist.HostPort
	for _, c := range slices.Concat(pod.InitContainers, pod.Containers) {
		for _, p := range c.Ports {
			if p.HostPort == 0 {
				continue
			}
			protocol := string(p.Protocol)
			if protocol == "" {
				protocol = string(corev1.ProtocolTCP)
			}
			out = append(out, pkgallowlist.HostPort{Protocol: protocol, HostPort: int(p.HostPort), ContainerPort: int(p.ContainerPort)})
		}
	}
	slices.SortFunc(out, func(a, b pkgallowlist.HostPort) int {
		return int(a.HostPort) - int(b.HostPort)
	})
	return out
}

// The seeded router entry declares exactly the host ports the rendered pod
// publishes, and hands them to every container the node matches an entry against.
func TestChartRouterEntryDeclaresItsHostPorts(t *testing.T) {
	t.Parallel()
	https := pkgallowlist.HostPort{Protocol: "TCP", HostPort: 443, ContainerPort: 8443}
	http := pkgallowlist.HostPort{Protocol: "TCP", HostPort: 80, ContainerPort: 8080}
	for _, tc := range []struct {
		name string
		args []string
		want []pkgallowlist.HostPort
	}{
		{name: "the cloud front door's port", args: digestArgs, want: []pkgallowlist.HostPort{https}},
		{name: "the baked front door's ports", args: bakedArgs, want: []pkgallowlist.HostPort{http, https}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			seed := renderedSeed(t, out)
			entry := seed.Workloads[routerEntryName(t, seed)]
			declared := []pkgallowlist.HostPort(entry.HostPorts)
			pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
			if published := publishedHostPorts(pod); !slices.Equal(declared, published) {
				t.Fatalf("entry declares %+v, the rendered pod publishes %+v", declared, published)
			}
			if !slices.Equal(declared, tc.want) {
				t.Fatalf("entry declares %+v, want %+v", declared, tc.want)
			}
			index := seed.BuildIndex()
			for _, launch := range secrets.WorkloadContainers(running(t, seed, pod)) {
				if !index.GrantsHostPorts(launch, declared) {
					t.Errorf("the entry hands %+v to no declaration admitting %q", declared, launch.Argv)
				}
			}
		})
	}
}
