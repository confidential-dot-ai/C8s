package helmchart

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// observedMounts classifies a rendered container's volume mounts the way the
// node plugin would on a node with no encrypted scratch, the least the
// chart's policies must admit: tmpfs-backed volumes (memory emptyDirs,
// Secrets, projected and downward-API volumes) are memory; ConfigMaps, PVCs
// and disk emptyDirs are of unknown storage; a hostPath is a host mount with
// the volumeMount's access mode.
func observedMounts(t *testing.T, spec corev1.PodSpec, c corev1.Container) []pkgallowlist.ObservedMount {
	t.Helper()
	volumes := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		volumes[v.Name] = v
	}
	out := make([]pkgallowlist.ObservedMount, 0, len(c.VolumeMounts))
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
			mount.Class, mount.ReadOnly, mount.HostSourceDigest = pkgallowlist.MountHost, m.ReadOnly, digest
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
	out, err := helmTemplate(t, bakedArgs...)
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
		t.Fatal("no baked component container was checked")
	}
}
