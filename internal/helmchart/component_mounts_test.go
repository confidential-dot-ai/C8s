package helmchart

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// observedMounts classifies a rendered container's mounts the way the node
// plugin would on a node with no encrypted scratch, the least the chart's
// policies must admit: tmpfs-backed volumes (memory emptyDirs, Secrets,
// projected and downward-API volumes) are memory; ConfigMaps, PVCs and disk
// emptyDirs are of unknown storage; a hostPath is a host mount, read-only only
// with recursiveReadOnly and no propagation, as kubelet binds it recursively.
// The kubelet and containerd add their platform mounts too.
func observedMounts(t *testing.T, spec corev1.PodSpec, c corev1.Container) []pkgallowlist.ObservedMount {
	t.Helper()
	volumes := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		volumes[v.Name] = v
	}
	platform := []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev/shm"}
	terminationLog := c.TerminationMessagePath
	if terminationLog == "" {
		terminationLog = corev1.TerminationMessagePathDefault
	}
	platform = append(platform, terminationLog)
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		platform = append(platform, "/var/run/secrets/kubernetes.io/serviceaccount")
	}
	out := make([]pkgallowlist.ObservedMount, 0, len(c.VolumeMounts)+len(platform))
	for _, destination := range platform {
		out = append(out, pkgallowlist.ObservedMount{Destination: destination, Class: pkgallowlist.MountPlatform})
	}
	for _, m := range c.VolumeMounts {
		v, ok := volumes[m.Name]
		if !ok {
			t.Fatalf("container %s mounts undeclared volume %q", c.Name, m.Name)
		}
		mount := pkgallowlist.ObservedMount{Destination: m.MountPath, Class: pkgallowlist.MountData, Storage: pkgallowlist.MountUnknown}
		switch {
		case v.HostPath != nil:
			digest, err := pkgallowlist.HostSourceDigest(v.HostPath.Path)
			if err != nil {
				t.Fatalf("container %s volume %q: %v", c.Name, m.Name, err)
			}
			recursive := m.RecursiveReadOnly != nil && *m.RecursiveReadOnly == corev1.RecursiveReadOnlyEnabled
			private := m.MountPropagation == nil || *m.MountPropagation == corev1.MountPropagationNone
			mount.Class, mount.ReadOnly, mount.HostSourceDigest = pkgallowlist.MountHost, m.ReadOnly && recursive && private, digest
		case v.EmptyDir != nil:
			mount.Class = pkgallowlist.MountEmptyDir
			if v.EmptyDir.Medium == corev1.StorageMediumMemory {
				mount.Storage = pkgallowlist.MountMemory
			}
		case v.Secret != nil, v.Projected != nil, v.DownwardAPI != nil:
			mount.Storage = pkgallowlist.MountMemory
		case v.ConfigMap != nil, v.PersistentVolumeClaim != nil:
		default:
			t.Fatalf("container %s volume %q has a source this test does not classify", c.Name, m.Name)
		}
		out = append(out, mount)
	}
	return out
}

// A baked node runs the components with the launch-contract mounts the node
// image adds (node config, inventory socket); the seed it measures must admit
// each of them.
func TestChartBakedComponentMountsPassTheirPolicy(t *testing.T) {
	checkComponentMounts(t, bakedArgs)
}

// Off a baked node volumed runs as a DaemonSet, with the host's /dev at /dev.
func TestChartVolumedDaemonSetMountsPassTheirPolicy(t *testing.T) {
	args := slices.Clone(bakedArgs)
	args[slices.Index(args, "node.baked=true")] = "node.baked=false"
	checkComponentMounts(t, append(args,
		"--set", "volumed.enabled=true",
		"--set", "volumed.image.digest=sha256:"+strings.Repeat("3", 64)))
}

func checkComponentMounts(t *testing.T, args []string) {
	t.Helper()
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	index := seed.BuildIndex()
	entrypoints := map[string][]string{}
	for _, w := range seed.Workloads {
		for _, c := range w.Containers {
			if c.Command.Policy == pkgallowlist.PolicyExact && (c.PinsAtMostCommand() || strings.Contains(c.Image, "nginx-unprivileged@")) {
				entrypoints[c.Digest.String()] = c.Command.Argv
			}
		}
	}
	checked := 0
	for _, w := range renderedPodSpecs(t, out) {
		for _, c := range append(append([]corev1.Container{}, w.spec.InitContainers...), w.spec.Containers...) {
			digest := imageDigest(c.Image)
			entrypoint, ok := entrypoints[digest]
			if !ok {
				continue
			}
			argv := effectiveArgv(c)
			if len(c.Command) == 0 {
				argv = append(append([]string{}, entrypoint...), c.Args...)
			}
			mounts := observedMounts(t, w.spec, c)
			running := pkgallowlist.RunningContainer{Digest: digest, Argv: argv, Mounts: mounts, Env: &pkgallowlist.EnvObservation{}}
			checked++
			if !index.AdmitsContainer(running) {
				t.Errorf("seed refuses %s/%s container %s with mounts %+v", w.kind, w.name, c.Name, mounts)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no component container was checked")
	}
}

// The plugin and CDS refuse a seed with an unclean mount path when they load
// it; the chart fails the render first.
func TestChartRefusesUncleanMountPaths(t *testing.T) {
	for name, args := range map[string][]string{
		"runtimeDir with a trailing slash": {"--set-string", "nriImagePolicy.hostPaths.runtimeDir=/var/run/nri-image-policy/"},
		"relative runtimeDir":              {"--set-string", "nriImagePolicy.hostPaths.runtimeDir=var/run/nri-image-policy"},
		"unclean denyBelow":                {"--set-string", "router.nginx.denyBelow[0]=/usr/../usr"},
		"empty local-path data dir":        {"--set-string", "rke2.localPathHelper.dataDir="},
		"volumed cgroup root with a trailing slash": {"--set", "node.baked=false", "--set", "volumed.enabled=true",
			"--set", "volumed.image.digest=sha256:" + strings.Repeat("3", 64), "--set-string", "volumed.hostPaths.cgroupRoot=/sys/fs/cgroup/"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := helmTemplate(t, append(append([]string{}, bakedArgs...), args...)...)
			if err == nil {
				t.Fatalf("helm template %q rendered, want a failure", args)
			}
			if !strings.Contains(string(out), "clean absolute path") {
				t.Fatalf("helm template %q failed without naming the path: %s", args, out)
			}
		})
	}
}

func TestRouterNginxArgumentsArePinned(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	ctr := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	digest := imageDigest(ctr.Image)
	var command []string
	for _, w := range seed.Workloads {
		for _, c := range w.Containers {
			if c.Digest.String() == digest {
				if c.Args.Policy != pkgallowlist.PolicyExact {
					t.Fatal("nginx still admits open arguments")
				}
				command = c.Command.Argv
			}
		}
	}
	if len(command) == 0 {
		t.Fatal("nginx entry missing")
	}
	if !slices.Equal(ctr.Command, command) {
		t.Fatalf("rendered command %q differs from policy %q", ctr.Command, command)
	}
	index := seed.BuildIndex()
	if !index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: digest, Argv: append(slices.Clone(command), ctr.Args...)}) {
		t.Fatal("rendered nginx invocation refused")
	}
	for _, args := range [][]string{{"-g", "load_module /m/evil.so;"}, {"-c", "/m/nginx.conf"}, {"-p", "/m"}, {"-g", "daemon off;", "-c", "/m/nginx.conf"}, {}} {
		if index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: digest, Argv: append(slices.Clone(command), args...)}) {
			t.Fatalf("nginx override accepted: %q", args)
		}
	}
	// The base is used as the sandbox privilege exemption; it must enforce
	// the same argv pin as the served entry.
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	for _, args := range [][]string{{"-g", "load_module /m/evil.so;"}, {"-c", "/m/nginx.conf"}} {
		if base.BuildIndex().AdmitsProcess(pkgallowlist.RunningContainer{Digest: digest, Argv: append(slices.Clone(command), args...)}) {
			t.Fatalf("base exempted nginx override: %q", args)
		}
	}
}
