package webhook

import (
	"os/exec"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	chartOperatorDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	chartRuntimeDir     = "/var/run/nri-image-policy"
)

// chartSeed renders the chart with the operator image derived and returns the
// allowlist seed it serves.
func chartSeed(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	out, err := exec.Command("helm", "template", "c8s", "../helmchart/c8s",
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--show-only", "templates/cds.yaml",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "image.digest="+chartOperatorDigest,
		"--set", "attestationApi.image.tag=dev",
		"--set", "armtlsMesh.image.tag=dev",
		"--set", "nriImagePolicy.image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
		"--set-string", "router.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000",
		"--set-string", "nriImagePolicy.hostPaths.runtimeDir="+chartRuntimeDir,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, doc := range strings.Split(string(out), "\n---\n") {
		var cm corev1.ConfigMap
		if err := yaml.Unmarshal([]byte(doc), &cm); err != nil || cm.Name != "c8s-cds-allowlist-seed" {
			continue
		}
		seed, err := allowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		return seed
	}
	t.Fatal("the chart rendered no allowlist seed")
	return nil
}

// observedSidecarMounts classifies an injected sidecar's mounts the way the
// node does: the webhook's volumes and the pod's discovery volume are memory
// emptyDirs, the reload-watch volume is a Secret, and on a node with the
// inventory the NRI plugin adds its socket directory read-only.
func observedSidecarMounts(t *testing.T, pod *corev1.Pod, c corev1.Container, inventory bool) []allowlist.ObservedMount {
	t.Helper()
	volumes := map[string]corev1.Volume{}
	for _, v := range pod.Spec.Volumes {
		volumes[v.Name] = v
	}
	mounts := []allowlist.ObservedMount{{Destination: "/etc/hosts", Class: allowlist.MountPlatform}}
	for _, m := range c.VolumeMounts {
		v, ok := volumes[m.Name]
		if !ok {
			t.Fatalf("%s mounts undeclared volume %q", c.Name, m.Name)
		}
		mount := allowlist.ObservedMount{Destination: m.MountPath, Class: allowlist.MountEmptyDir, Storage: allowlist.MountMemory}
		if v.Secret != nil {
			mount.Class = allowlist.MountData
		}
		mounts = append(mounts, mount)
	}
	if inventory && workloadclaims.IsSocketConsumer(c.Name) {
		digest, err := allowlist.HostSourceDigest(chartRuntimeDir)
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, allowlist.ObservedMount{Destination: workloadclaims.SidecarSocketDir, Class: allowlist.MountHost, ReadOnly: true, HostSourceDigest: digest})
	}
	return mounts
}

// Every sidecar this webhook injects, with every combination of the optional
// discovery, reload-watch and inventory socket mounts, must be admitted by the
// chart's operator entry, and must still be dropped from workload matching.
// The chart pins the sidecars' mount tables exactly, so this is what keeps the
// webhook's fixed destinations and the chart's in step.
func TestChartSeedAdmitsInjectedSidecars(t *testing.T) {
	seed := chartSeed(t)
	index := seed.BuildIndex()
	for _, tc := range []struct {
		name                         string
		discovery, reload, inventory bool
	}{
		{name: "plain"},
		{name: "discovery", discovery: true},
		{name: "reload watch", reload: true},
		{name: "discovery and reload watch", discovery: true, reload: true},
		{name: "inventory", inventory: true},
		{name: "everything", discovery: true, reload: true, inventory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			pod.Annotations = map[string]string{
				AnnotationWorkload: "api",
				AnnotationSecrets:  "DB=/api/db",
				AnnotationVolumes:  "weights=/api/weights",
			}
			if tc.discovery {
				pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "discovery", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}})
				pod.Annotations[AnnotationDiscoveryVolume] = "discovery"
				pod.Annotations[AnnotationDiscoveryOut] = discoveryMountPath + "/discovery.json"
				pod.Annotations[AnnotationDiscoveryCDSCertURL] = "/.well-known/cds-cert.pem"
				pod.Annotations[AnnotationDiscoveryPublicTLSMode] = "cds"
			}
			if tc.reload {
				pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "public-tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "public-tls"}}})
				pod.Annotations[AnnotationReloadWatchVolume] = "public-tls"
				pod.Annotations[AnnotationReloadWatchPaths] = reloadWatchMountPath + "/tls.crt"
			}
			inj, err := parseAnnotations(pod)
			if err != nil {
				t.Fatalf("parseAnnotations: %v", err)
			}
			cfg := secretsConfig()
			if tc.inventory {
				cfg.WorkloadClaimsHostDir = chartRuntimeDir
			}
			mutatePod(pod, inj, cfg)

			var injected []workloadclaims.SandboxContainer
			for _, c := range pod.Spec.InitContainers {
				if !workloadclaims.IsInjectedContainerName(c.Name) {
					continue
				}
				argv := c.Command
				if len(argv) == 0 {
					argv = append([]string{secrets.InjectedBinary}, c.Args...)
				}
				mounts := observedSidecarMounts(t, pod, c, tc.inventory)
				if !index.AdmitsContainer(allowlist.RunningContainer{Digest: chartOperatorDigest, Argv: argv, Mounts: mounts, Env: &allowlist.EnvObservation{}}) {
					t.Errorf("chart seed refuses injected %s with mounts %+v", c.Name, mounts)
				}
				injected = append(injected, workloadclaims.SandboxContainer{Digest: chartOperatorDigest, Argv: argv, Mounts: mounts})
			}
			if len(injected) != 4 {
				t.Fatalf("injected %d containers, want the cert sidecar, cert-wait gate, secret fetcher, and volume fetcher", len(injected))
			}
			if left := secrets.WorkloadContainers(seed, injected); len(left) != 0 {
				t.Errorf("the drop set keeps injected containers: %+v", left)
			}
		})
	}
}
