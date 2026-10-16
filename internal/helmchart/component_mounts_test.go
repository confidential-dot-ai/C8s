package helmchart

import (
	"maps"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// kubeletExpand is the kubelet's $(VAR) expansion of one argv token: $$ is a
// literal $, a reference to a variable the container defines becomes its
// value, and anything else stays as written.
func kubeletExpand(token string, env map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(token); i++ {
		if token[i] != '$' || i+1 == len(token) {
			b.WriteByte(token[i])
			continue
		}
		switch token[i+1] {
		case '$':
			b.WriteByte('$')
			i++
		case '(':
			end := strings.IndexByte(token[i:], ')')
			if end < 0 {
				b.WriteByte('$')
				continue
			}
			name := token[i+2 : i+end]
			if value, ok := env[name]; ok {
				b.WriteString(value)
			} else {
				b.WriteString(token[i : i+end+1])
			}
			i += end
		default:
			b.WriteByte('$')
		}
	}
	return b.String()
}

// runtimeArgv is the OCI process.args the runtime starts: the container's
// command and args after kubelet expansion, with the image entrypoint in
// place of an absent command.
func runtimeArgv(c corev1.Container, entrypoint []string) []string {
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
		if e.ValueFrom != nil {
			env[e.Name] = "192.0.2.1"
		}
	}
	command := c.Command
	if len(command) == 0 {
		command = entrypoint
	}
	var argv []string
	for _, token := range slices.Concat(command, c.Args) {
		argv = append(argv, kubeletExpand(token, env))
	}
	return argv
}

// kubeletServiceEnv is what the kubelet adds to every container of a pod
// with service links off: the variables of the default namespace's
// kubernetes Service.
var kubeletServiceEnv = []string{
	"KUBERNETES_SERVICE_HOST=10.96.0.1",
	"KUBERNETES_SERVICE_PORT=443",
	"KUBERNETES_SERVICE_PORT_HTTPS=443",
	"KUBERNETES_PORT=tcp://10.96.0.1:443",
	"KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
	"KUBERNETES_PORT_443_TCP_PROTO=tcp",
	"KUBERNETES_PORT_443_TCP_PORT=443",
	"KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1",
}

// launchEnv is the environment a node reports for c, plus extra: containerd's
// HOSTNAME, the image config's Env (containerd's default PATH when it sets
// none), the kubelet's service variables, then the container's env, a
// valueFrom resolved to a placeholder. A pod with service links on fails the
// test: the kubelet would add variables for every Service in the namespace.
func launchEnv(t *testing.T, spec corev1.PodSpec, c corev1.Container, imageEnv map[string]string, extra ...string) *pkgallowlist.EnvObservation {
	t.Helper()
	if spec.EnableServiceLinks == nil || *spec.EnableServiceLinks {
		t.Fatalf("container %s runs in a pod with service links on", c.Name)
	}
	entries := []string{"HOSTNAME=c8s-0"}
	if _, ok := imageEnv["PATH"]; !ok {
		entries = append(entries, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	for _, name := range slices.Sorted(maps.Keys(imageEnv)) {
		entries = append(entries, name+"="+imageEnv[name])
	}
	entries = append(entries, kubeletServiceEnv...)
	for _, e := range c.Env {
		value := e.Value
		if e.ValueFrom != nil {
			value = "192.0.2.1"
		}
		entries = append(entries, e.Name+"="+value)
	}
	env, err := pkgallowlist.ObserveLaunchEnv(append(entries, extra...))
	if err != nil {
		t.Fatalf("container %s env: %v", c.Name, err)
	}
	return env
}

// observedMounts classifies a rendered container's mounts the way the node
// plugin does on a node without encrypted scratch, the least the chart's
// entries must admit: tmpfs-backed volumes (memory emptyDirs, Secrets,
// projected and downward-API volumes) are memory, ConfigMaps, PVCs and disk
// emptyDirs are of unknown storage, and a hostPath is a host mount whose
// source containerd resolves through symlinks (resolveVarRun: /var/run is
// /run). The kubelet and containerd add their platform mounts too.
func observedMounts(t *testing.T, spec corev1.PodSpec, c corev1.Container, resolveVarRun bool) []pkgallowlist.ObservedMount {
	t.Helper()
	volumes := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		volumes[v.Name] = v
	}
	var out []pkgallowlist.ObservedMount
	for _, destination := range []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev/shm", "/dev/termination-log", "/var/run/secrets/kubernetes.io/serviceaccount"} {
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
			source := v.HostPath.Path
			if rest, ok := strings.CutPrefix(source, "/var/run"); resolveVarRun && ok && (rest == "" || rest[0] == '/') {
				source = "/run" + rest
			}
			digest, err := pkgallowlist.HostSourceDigest(source)
			if err != nil {
				t.Fatalf("container %s volume %q: %v", c.Name, m.Name, err)
			}
			mount = pkgallowlist.ObservedMount{Destination: m.MountPath, Class: pkgallowlist.MountHost, Storage: pkgallowlist.MountUnknown, HostSourceDigest: digest, ReadOnly: m.ReadOnly}
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

// componentPin is what values.yaml declares for one component image: the
// entrypoint it runs and its image config's Env.
type componentPin struct {
	entrypoint []string
	imageEnv   map[string]string
}

// componentPins maps each component digest a render sets to its
// componentPin, from the render's own --set arguments, the CDS digest
// helmTemplate pins and the nginx digest the router renders.
func componentPins(t *testing.T, out string, args []string) map[string]componentPin {
	t.Helper()
	entrypoints, envs := componentPinValues(t), componentImageEnvValues(t)
	values := map[string]componentPin{}
	for key, entrypoint := range entrypoints {
		values[key] = componentPin{entrypoint: entrypoint, imageEnv: envs[key]}
	}
	pins := map[string]componentPin{"sha256:0000000000000000000000000000000000000000000000000000000000000001": values["cds.image"]}
	for _, arg := range args {
		key, digest, ok := strings.Cut(arg, ".digest=")
		if !ok {
			continue
		}
		if pin, ok := values[key]; ok {
			pins[digest] = pin
		}
	}
	for _, w := range renderedPodSpecs(t, out) {
		for _, c := range w.spec.Containers {
			if strings.Contains(c.Image, "nginx-unprivileged@") {
				pins[imageDigest(c.Image)] = values["router.nginx"]
			}
		}
	}
	return pins
}

// injectedShape reports whether a container is one of the shapes the chart
// declares for the sidecars the webhook injects: pinned to the C8s binary in
// an injected mode, with the per-pod args left open.
func injectedShape(c pkgallowlist.Container) bool {
	return c.Command.Policy == pkgallowlist.PolicyExact && len(c.Command.Argv) == 2 && c.Command.Argv[0] == "/c8s" &&
		slices.Contains([]string{"get-cert", "probe-file", "get-secret", "get-volume"}, c.Command.Argv[1])
}

// Every component container the chart renders must be admitted by the seed,
// and by the plugin's base where one renders, under exactly the argv, mount
// table and environment it is rendered with: one argument more, one mount
// fewer or one more, a loader variable or a redirected PATH is refused. On
// default, bare-metal and baked renders alike, no component entry leaves env
// open, nor args or mounts except the injected sidecar shapes, whose args are
// per pod.
func TestChartComponentShapesAreExact(t *testing.T) {
	t.Parallel()
	digests := []string{}
	for valuePath, digest := range componentTestDigests {
		digests = append(digests, "--set", valuePath+".digest="+digest)
	}
	derived := append([]string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}, digests...)
	measurements := strings.Repeat("a", 96)
	measurementsConfig := writeChartImagePolicy(t, `{"schema_version":"1","tee":"tdx","measurements":[{"name":"first","mrtd":"`+measurements+`"}]}`)
	for _, tc := range []struct {
		name string
		args []string
		base bool
	}{
		{"default", append(slices.Clone(derived), "--set", "volumed.enabled=true", "--set", "attestationApi.enabled=true"), true},
		{"gke", append(slices.Clone(derived), "--set", "attestationApi.cvmMode=gke", "--set", "attestationApi.enabled=true", "--set", "volumed.enabled=true"), true},
		{"bare-metal", append(slices.Clone(derived),
			"--set", "attestationApi.cvmMode=bare-metal", "--set", "attestationApi.enabled=false",
			"--set", "nriImagePolicy.baked=true", "--set", "router.attest.enabled=true", "--set", "volumed.enabled=true"), false},
		{"bare-metal router gate", append(slices.Clone(derived),
			"--set", "attestationApi.cvmMode=bare-metal", "--set", "attestationApi.enabled=false", "--set", "nriImagePolicy.baked=true",
			"--set", "router.attest.enabled=true", "--set", "router.attest.expectedWorkload=front", "--set", "router.hostPort.enabled=false"), false},
		{"webpki and discovery", append(slices.Clone(derived),
			"--set", "router.publicTLS.mode=webpki", "--set", "router.publicTLS.secretName=pub", "--set", "router.discovery.enabled=true",
			"--set-file", "cds.measurementsConfig="+measurementsConfig, "--set-file", "armtlsMesh.measurementsConfig="+measurementsConfig,
			"--set", "cds.measurements={"+measurements+"}"), true},
		{"acme", append(slices.Clone(derived),
			"--set", "router.publicTLS.mode=acme", "--set", "router.service.type=LoadBalancer", "--set-json", `router.san=["a.example.com"]`), true},
		{"escaped operator args", append(slices.Clone(derived), "--set-json", `operator.extraArgs=["cost $5","$(a $$","$$(POD_NAME)"]`), true},
		{"baked", append(slices.Clone(bakedArgs), "--set", "armtlsMesh.image.digest=sha256:"+strings.Repeat("2", 64)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			pins := componentPins(t, out, tc.args)
			sources := map[string]*pkgallowlist.Allowlist{"seed": renderedSeed(t, out)}
			if tc.base {
				base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
				sources["base"] = &base
			}
			for source, al := range sources {
				for name, w := range al.Workloads {
					for _, c := range w.Containers {
						if _, ok := pins[c.Digest.String()]; !ok {
							continue
						}
						if c.Env.Policy != pkgallowlist.PolicyMatch {
							t.Errorf("%s entry %s leaves env %q", source, name, c.Env.Policy)
						}
						if injectedShape(c) {
							continue
						}
						if c.Args.Policy == pkgallowlist.PolicyAny || c.Mounts.Policy == pkgallowlist.PolicyAny {
							t.Errorf("%s entry %s leaves args %q or mounts %q open", source, name, c.Args.Policy, c.Mounts.Policy)
						}
					}
				}
			}
			checked := 0
			for _, w := range renderedPodSpecs(t, out) {
				for _, c := range slices.Concat(w.spec.InitContainers, w.spec.Containers) {
					digest := imageDigest(c.Image)
					pin, ok := pins[digest]
					if !ok {
						continue
					}
					checked++
					if len(c.Command) == 0 {
						t.Errorf("%s/%s runs its image's ENTRYPOINT, which the allowlist cannot see; render its command", w.name, c.Name)
					}
					argv := runtimeArgv(c, pin.entrypoint)
					launch := func(extra ...string) *pkgallowlist.EnvObservation {
						return launchEnv(t, w.spec, c, pin.imageEnv, extra...)
					}
					for _, resolve := range []bool{false, true} {
						mounts := observedMounts(t, w.spec, c, resolve)
						for source, al := range sources {
							checkExactShape(t, source+" "+w.name+"/"+c.Name, al.BuildIndex(), digest, argv, mounts, launch)
						}
					}
				}
			}
			if checked == 0 {
				t.Fatal("no component container was checked")
			}
		})
	}
}

// A baked router reads its nginx configuration from the image, so the seed
// refuses a ConfigMap swapped in over that directory.
func TestChartBakedNginxRefusesConfigMapConfig(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	spec := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	i := slices.IndexFunc(spec.Containers, func(c corev1.Container) bool { return c.Name == "nginx" })
	if i < 0 {
		t.Fatal("baked router has no nginx container")
	}
	nginx := spec.Containers[i]
	argv := runtimeArgv(nginx, componentPinValues(t)["router.nginx"])
	if !slices.Contains(argv, "/usr/lib/c8s/router-nginx/nginx.conf") {
		t.Errorf("baked nginx argv = %q, want -c /usr/lib/c8s/router-nginx/nginx.conf", argv)
	}
	index := renderedSeed(t, out).BuildIndex()
	admits := func() bool {
		return index.AdmitsContainer(pkgallowlist.RunningContainer{
			Digest: imageDigest(nginx.Image), Argv: argv, Mounts: observedMounts(t, spec, nginx, false), Env: &pkgallowlist.EnvObservation{},
		})
	}
	if !admits() {
		t.Fatal("baked seed refuses nginx as rendered")
	}
	v := slices.IndexFunc(spec.Volumes, func(v corev1.Volume) bool { return v.Name == "nginx-config" })
	if v < 0 || spec.Volumes[v].HostPath == nil || spec.Volumes[v].HostPath.Path != "/usr/lib/c8s/router-nginx" {
		t.Fatalf("baked router lacks the nginx-config hostPath /usr/lib/c8s/router-nginx: %+v", spec.Volumes)
	}
	spec.Volumes[v].VolumeSource = corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}
	if admits() {
		t.Error("baked seed admits nginx with its configuration from a ConfigMap")
	}
}

// checkExactShape fails unless index admits the container as rendered and
// refuses it with an extra argument, without any one of its own mounts, with
// one mount more, or with LD_PRELOAD set or PATH pointed elsewhere. launch
// returns its launch environment with the given variables set over it.
func checkExactShape(t *testing.T, what string, index *pkgallowlist.Index, digest string, argv []string, mounts []pkgallowlist.ObservedMount, launch func(...string) *pkgallowlist.EnvObservation) {
	t.Helper()
	env := launch()
	admits := func(argv []string, mounts []pkgallowlist.ObservedMount) bool {
		return index.AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: argv, Mounts: mounts, Env: env})
	}
	if !admits(argv, mounts) {
		t.Errorf("%s: refused as rendered: argv %q, mounts %+v", what, argv, mounts)
		return
	}
	for _, variable := range []string{"LD_PRELOAD=/tmp/hook.so", "PATH=/tmp"} {
		if index.AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: argv, Mounts: mounts, Env: launch(variable)}) {
			t.Errorf("%s: admitted with %s", what, variable)
		}
	}
	if admits(append(slices.Clone(argv), "--kubeconfig=/tmp/kubeconfig"), mounts) {
		t.Errorf("%s: admitted with an extra argument", what)
	}
	extra := pkgallowlist.ObservedMount{Destination: "/extra", Class: pkgallowlist.MountEmptyDir, Storage: pkgallowlist.MountMemory}
	if admits(argv, append(slices.Clone(mounts), extra)) {
		t.Errorf("%s: admitted with an extra mount", what)
	}
	for i, m := range mounts {
		if m.Class == pkgallowlist.MountPlatform {
			continue
		}
		if admits(argv, slices.Delete(slices.Clone(mounts), i, i+1)) {
			t.Errorf("%s: admitted without its mount at %s", what, m.Destination)
		}
	}
}

func TestChartMemoryVolumesHaveSizeLimit(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, w := range renderedPodSpecs(t, out) {
		for _, v := range w.spec.Volumes {
			if v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory {
				continue
			}
			if v.EmptyDir.SizeLimit == nil {
				t.Errorf("%s/%s volume %q: memory emptyDir without sizeLimit", w.kind, w.name, v.Name)
			}
		}
	}
}

// The schema accepts any positive Kubernetes quantity as the store's memory
// limit and renders it as the volume's sizeLimit.
func TestChartAcceptsCDSMemorySizeLimitQuantities(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		flag, value, want string
	}{
		{"--set-string", "64Mi", "64Mi"},
		{"--set", "67108864", "64Mi"},
	} {
		out, err := helmTemplate(t, tc.flag, "cds.persistence.memorySizeLimit="+tc.value)
		if err != nil {
			t.Errorf("helm template %s memorySizeLimit=%s: %v\n%s", tc.flag, tc.value, err, out)
			continue
		}
		pod := renderedDeployment(t, out, "c8s-cds").Spec.Template.Spec
		i := slices.IndexFunc(pod.Volumes, func(v corev1.Volume) bool { return v.Name == "data" })
		if i < 0 || pod.Volumes[i].EmptyDir == nil || pod.Volumes[i].EmptyDir.SizeLimit == nil {
			t.Errorf("memorySizeLimit=%s: no data emptyDir with a sizeLimit in %+v", tc.value, pod.Volumes)
			continue
		}
		if got := pod.Volumes[i].EmptyDir.SizeLimit; got.Cmp(resource.MustParse(tc.want)) != 0 {
			t.Errorf("memorySizeLimit=%s: sizeLimit = %s, want %s", tc.value, got, tc.want)
		}
	}
	for _, value := range []string{"0Mi"} {
		if out, err := helmTemplate(t, "--set-string", "cds.persistence.memorySizeLimit="+value); err == nil {
			t.Errorf("helm template memorySizeLimit=%s succeeded, want a schema error\n%s", value, out)
		}
	}
}
