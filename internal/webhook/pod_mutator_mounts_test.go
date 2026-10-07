package webhook

import (
	"maps"
	"os"
	"os/exec"
	"slices"
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
	chartRuntimeDir     = "/run/nri-image-policy"
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
		"--set", "router.routing.allowUnpinnedCDS=true",
		"--set", "image.digest="+chartOperatorDigest,
		"--set", "attestationApi.image.tag=dev",
		"--set", "armtlsMesh.image.tag=dev",
		"--set", "nriImagePolicy.image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
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

// chartImageEnv reads the operator image's Env from the chart's c8sComponents.
func chartImageEnv(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../helmchart/c8s/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		Components []struct {
			ValuePath string            `json:"valuePath"`
			ImageEnv  map[string]string `json:"imageEnv"`
		} `json:"c8sComponents"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	for _, c := range values.Components {
		if c.ValuePath == "image" {
			return c.ImageEnv
		}
	}
	t.Fatal("values.yaml declares no operator image")
	return nil
}

// sidecarEnv is the environment a node reports for an injected sidecar, plus
// extra: containerd's HOSTNAME, the image's Env, the kubelet's variables for
// the API server's Service, and the sidecar's env, a valueFrom resolved to a
// placeholder. A pod left with service links on fails the test: the kubelet
// would add variables for every Service in the namespace.
func sidecarEnv(t *testing.T, pod *corev1.Pod, c corev1.Container, imageEnv map[string]string, extra ...string) *allowlist.EnvObservation {
	t.Helper()
	if pod.Spec.EnableServiceLinks == nil || *pod.Spec.EnableServiceLinks {
		t.Fatal("the injected pod has service links on")
	}
	entries := []string{"HOSTNAME=api-0"}
	for _, name := range slices.Sorted(maps.Keys(imageEnv)) {
		entries = append(entries, name+"="+imageEnv[name])
	}
	entries = append(entries,
		"KUBERNETES_SERVICE_HOST=10.96.0.1", "KUBERNETES_SERVICE_PORT=443", "KUBERNETES_SERVICE_PORT_HTTPS=443",
		"KUBERNETES_PORT=tcp://10.96.0.1:443", "KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
		"KUBERNETES_PORT_443_TCP_PROTO=tcp", "KUBERNETES_PORT_443_TCP_PORT=443", "KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1")
	for _, e := range c.Env {
		value := e.Value
		if e.ValueFrom != nil {
			value = "192.0.2.1"
		}
		entries = append(entries, e.Name+"="+value)
	}
	env, err := allowlist.ObserveLaunchEnv(append(entries, extra...))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// observedSidecarMounts classifies an injected sidecar's mounts the way the
// node does: the webhook's volumes and the pod's discovery volume are memory
// emptyDirs, the reload-watch volume is a Secret, and on a node with the
// inventory the NRI plugin adds its socket directory read-only, which it
// observes as a platform mount.
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
		mounts = append(mounts, allowlist.ObservedMount{Destination: workloadclaims.SidecarSocketDir, Class: allowlist.MountPlatform, ReadOnly: true})
	}
	return mounts
}

// Every sidecar this webhook injects, with every combination of the optional
// discovery, reload-watch and inventory socket mounts, must be admitted by the
// chart's operator entry with the environment it launches with, refused with
// a loader variable added, and still dropped from workload matching. The
// chart pins the sidecars' mount tables exactly and matches their env by
// name, so this is what keeps the webhook's fixed destinations and variables
// and the chart's in step.
func TestChartSeedAdmitsInjectedSidecars(t *testing.T) {
	seed := chartSeed(t)
	index := seed.BuildIndex()
	imageEnv := chartImageEnv(t)
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
			inj, err := parseAnnotations(pod, "default")
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
				env := sidecarEnv(t, pod, c, imageEnv)
				if !index.AdmitsContainer(allowlist.RunningContainer{Digest: chartOperatorDigest, Argv: argv, Mounts: mounts, Env: env}) {
					t.Errorf("chart seed refuses injected %s with mounts %+v", c.Name, mounts)
				}
				if index.AdmitsContainer(allowlist.RunningContainer{Digest: chartOperatorDigest, Argv: argv, Mounts: mounts, Env: sidecarEnv(t, pod, c, imageEnv, "LD_PRELOAD=/tmp/hook.so")}) {
					t.Errorf("chart seed admits injected %s with LD_PRELOAD", c.Name)
				}
				injected = append(injected, workloadclaims.SandboxContainer{Digest: chartOperatorDigest, Argv: argv, Mounts: mounts, Env: env})
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

// A socket directory observed as a host mount is a pod-spec hostPath, not the
// NRI plugin's own bind, so the seed refuses the sidecar and keeps it in
// workload matching.
func TestChartSeedRefusesHostSocketMount(t *testing.T) {
	seed := chartSeed(t)
	index := seed.BuildIndex()
	imageEnv := chartImageEnv(t)
	pod := podWithApp()
	pod.Annotations = map[string]string{AnnotationWorkload: "api"}
	inj, err := parseAnnotations(pod, "default")
	if err != nil {
		t.Fatalf("parseAnnotations: %v", err)
	}
	mutatePod(pod, inj, secretsConfig())
	i := slices.IndexFunc(pod.Spec.InitContainers, func(c corev1.Container) bool { return c.Name == workloadclaims.CertContainerName })
	if i < 0 {
		t.Fatal("no cert sidecar injected")
	}
	c := pod.Spec.InitContainers[i]
	digest, err := allowlist.HostSourceDigest(chartRuntimeDir)
	if err != nil {
		t.Fatal(err)
	}
	mounts := append(observedSidecarMounts(t, pod, c, false),
		allowlist.ObservedMount{Destination: workloadclaims.SidecarSocketDir, Class: allowlist.MountHost, ReadOnly: true, HostSourceDigest: digest})
	argv := c.Command
	if len(argv) == 0 {
		argv = append([]string{secrets.InjectedBinary}, c.Args...)
	}
	env := sidecarEnv(t, pod, c, imageEnv)
	if index.AdmitsContainer(allowlist.RunningContainer{Digest: chartOperatorDigest, Argv: argv, Mounts: mounts, Env: env}) {
		t.Errorf("chart seed admits %s with a host socket mount %+v", c.Name, mounts)
	}
	ctr := workloadclaims.SandboxContainer{Digest: chartOperatorDigest, Argv: argv, Mounts: mounts, Env: env}
	if left := secrets.WorkloadContainers(seed, []workloadclaims.SandboxContainer{ctr}); len(left) != 1 {
		t.Errorf("WorkloadContainers dropped %s with a host socket mount, want it kept", c.Name)
	}
}

// A discovery or reload-watch volume the sidecar's mount rules cannot admit is
// refused at admission rather than by the node at container creation. A
// disk-backed emptyDir and a ConfigMap pass: encrypted scratch admits them.
func TestRejectUnpinnableSidecarVolumes(t *testing.T) {
	memory := corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}
	secret := corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "public-tls"}}
	hostPath := corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/srv/tls"}}
	pvc := corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "tls"}}
	for _, tc := range []struct {
		name              string
		discovery, reload *corev1.VolumeSource
		wantRefused       bool
	}{
		{name: "memory discovery", discovery: &memory},
		{name: "disk discovery", discovery: &corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{name: "secret discovery", discovery: &secret, wantRefused: true},
		{name: "hostPath discovery", discovery: &hostPath, wantRefused: true},
		{name: "secret reload watch", reload: &secret},
		{name: "configMap reload watch", reload: &corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}},
		{name: "projected reload watch", reload: &corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{}}},
		{name: "emptyDir reload watch", reload: &memory, wantRefused: true},
		{name: "hostPath reload watch", reload: &hostPath, wantRefused: true},
		{name: "PVC reload watch", reload: &pvc, wantRefused: true},
		{name: "undeclared discovery volume", wantRefused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			pod.Annotations = map[string]string{AnnotationWorkload: "api"}
			if tc.discovery != nil || tc.reload == nil {
				pod.Annotations[AnnotationDiscoveryVolume] = "discovery"
				pod.Annotations[AnnotationDiscoveryOut] = discoveryMountPath + "/discovery.json"
				pod.Annotations[AnnotationDiscoveryCDSCertURL] = "/.well-known/cds-cert.pem"
				pod.Annotations[AnnotationDiscoveryPublicTLSMode] = "cds"
			}
			if tc.discovery != nil {
				pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "discovery", VolumeSource: *tc.discovery})
			}
			if tc.reload != nil {
				pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "watched", VolumeSource: *tc.reload})
				pod.Annotations[AnnotationReloadWatchVolume] = "watched"
				pod.Annotations[AnnotationReloadWatchPaths] = reloadWatchMountPath + "/tls.crt"
			}
			inj, err := parseAnnotations(pod, "default")
			if err != nil {
				t.Fatalf("parseAnnotations: %v", err)
			}
			err = rejectUnpinnableSidecarVolumes(pod, inj)
			if refused := err != nil; refused != tc.wantRefused {
				t.Fatalf("rejectUnpinnableSidecarVolumes = %v, want refused %v", err, tc.wantRefused)
			}
		})
	}
}
