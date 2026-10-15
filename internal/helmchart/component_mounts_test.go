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

// A baked router reads its nginx configuration from the image, so the seed
// must refuse a ConfigMap swapped in over it.
func TestChartBakedNginxRefusesConfigMapConfig(t *testing.T) {
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	router := renderedDeployment(t, out, "c8s-router")
	spec := router.Spec.Template.Spec
	var nginx corev1.Container
	for _, c := range spec.Containers {
		if c.Name == "nginx" {
			nginx = c
		}
	}
	seed := renderedSeed(t, out)
	digest := imageDigest(nginx.Image)
	argv := effectiveArgv(nginx)
	for _, w := range seed.Workloads {
		for _, c := range w.Containers {
			if c.Digest.String() == digest && c.PinsAtMostCommand() && len(nginx.Command) == 0 {
				argv = append(slices.Clone(c.Command.Argv), nginx.Args...)
			}
		}
	}
	admits := func() bool {
		return seed.BuildIndex().AdmitsContainer(pkgallowlist.RunningContainer{
			Digest: digest, Argv: argv, Mounts: observedMounts(t, spec, nginx), Env: &pkgallowlist.EnvObservation{},
		})
	}
	if !admits() {
		t.Fatal("baked seed refuses nginx as rendered")
	}
	i := slices.IndexFunc(spec.Volumes, func(v corev1.Volume) bool { return v.Name == "nginx-config" })
	if i < 0 || spec.Volumes[i].HostPath == nil || spec.Volumes[i].HostPath.Path != "/usr/lib/c8s/router-nginx" {
		t.Fatalf("baked router lacks the nginx-config hostPath /usr/lib/c8s/router-nginx: %+v", spec.Volumes)
	}
	spec.Volumes[i].VolumeSource = corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}
	if admits() {
		t.Error("baked seed admits nginx with its configuration from a ConfigMap")
	}
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
			if c.PinsAtMostCommand() && c.Command.Policy == pkgallowlist.PolicyExact {
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
