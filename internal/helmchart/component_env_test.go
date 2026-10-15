package helmchart

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// runtimeTestEnv is what containerd and the kubelet add to a component
// container with service links off, with values a cluster could carry.
var runtimeTestEnv = map[string]string{
	"HOSTNAME":                      "c8s-operator-7d9f8-x2kq4",
	"KUBERNETES_SERVICE_HOST":       "10.43.0.1",
	"KUBERNETES_SERVICE_PORT":       "443",
	"KUBERNETES_SERVICE_PORT_HTTPS": "443",
	"KUBERNETES_PORT":               "tcp://10.43.0.1:443",
	"KUBERNETES_PORT_443_TCP":       "tcp://10.43.0.1:443",
	"KUBERNETES_PORT_443_TCP_PROTO": "tcp",
	"KUBERNETES_PORT_443_TCP_PORT":  "443",
	"KUBERNETES_PORT_443_TCP_ADDR":  "10.43.0.1",
}

// componentImage is what values.yaml declares about a component image.
type componentImage struct {
	entrypoint []string
	env        map[string]string
}

// componentImages reads the entrypoint and imageEnv values.yaml declares for
// each component image, keyed by its default repository.
func componentImages(t *testing.T) map[string]componentImage {
	t.Helper()
	raw, err := os.ReadFile("c8s/values.yaml")
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	var tree map[string]any
	if err := sigsyaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("parse values.yaml: %v", err)
	}
	at := func(path string) any {
		var cur any = tree
		for _, seg := range strings.Split(path, ".") {
			m, _ := cur.(map[string]any)
			cur = m[seg]
		}
		return cur
	}
	images := map[string]componentImage{}
	add := func(repository, entrypoint, imageEnv any) {
		image := componentImage{env: map[string]string{}}
		for _, token := range entrypoint.([]any) {
			image.entrypoint = append(image.entrypoint, token.(string))
		}
		for name, value := range imageEnv.(map[string]any) {
			image.env[name] = value.(string)
		}
		images[repository.(string)] = image
	}
	for _, c := range at("c8sComponents").([]any) {
		c := c.(map[string]any)
		if imageEnv, ok := c["imageEnv"]; ok {
			add(at(c["valuePath"].(string)+".repository"), c["entrypoint"], imageEnv)
		}
	}
	add(at("router.nginx.image.repository"), at("router.nginx.entrypoint"), at("router.nginx.imageEnv"))
	return images
}

// launchEnv observes the environment c launches with: containerd's
// HOSTNAME, the image's, the kubelet's, then the pod spec's, each overriding
// the one before. A downward-API value stands in as a fixed string; extra
// adds NAME=value entries on top.
func launchEnv(t *testing.T, imageEnv map[string]string, c corev1.Container, extra ...string) *pkgallowlist.EnvObservation {
	t.Helper()
	env := map[string]string{"HOSTNAME": runtimeTestEnv["HOSTNAME"]}
	maps.Copy(env, imageEnv)
	for name, value := range runtimeTestEnv {
		if name != "HOSTNAME" {
			env[name] = value
		}
	}
	for _, e := range c.Env {
		value := e.Value
		if e.ValueFrom != nil {
			value = "10.0.0.7"
		}
		env[e.Name] = value
	}
	entries := make([]string, 0, len(env)+len(extra))
	for name, value := range env {
		entries = append(entries, name+"="+value)
	}
	observation, err := pkgallowlist.ObserveLaunchEnv(append(entries, extra...))
	if err != nil {
		t.Fatalf("observe %s env: %v", c.Name, err)
	}
	return observation
}

// componentContainer is a rendered container running a component image.
type componentContainer struct {
	workload  string
	container corev1.Container
	digest    string
	image     componentImage
}

// renderedComponentContainers returns every container in out that runs a
// component image, and fails the test when a pod running one leaves service
// links on.
func renderedComponentContainers(t *testing.T, out string) []componentContainer {
	t.Helper()
	images := componentImages(t)
	var found []componentContainer
	for _, w := range renderedPodSpecs(t, out) {
		name := w.kind + "/" + w.name
		component := false
		for _, c := range append(slices.Clone(w.spec.InitContainers), w.spec.Containers...) {
			repository, digest, ok := strings.Cut(c.Image, "@")
			image, known := images[repository]
			if !ok || !known {
				continue
			}
			component = true
			found = append(found, componentContainer{workload: name, container: c, digest: digest, image: image})
		}
		if component && (w.spec.EnableServiceLinks == nil || *w.spec.EnableServiceLinks) {
			t.Errorf("%s runs a component image with service links on, want enableServiceLinks: false", name)
		}
	}
	return found
}

// loaderVariables are names the runtime's loader or a component's entrypoint
// reads code or code locations from.
var loaderVariables = []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "ENV", "GLIBC_TUNABLES", "NGINX_ENVSUBST_TEMPLATE_DIR"}

// Every component container the chart renders is admitted with the
// environment it launches with, and refused with a loader variable or a
// service-link variable added: the entries match env by name.
func TestChartComponentEntriesMatchEnv(t *testing.T) {
	bareMetal := []string{
		"--set", "attestationApi.cvmMode=bare-metal",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "image.digest=" + componentTestDigests["image"],
		"--set", "armtlsMesh.image.digest=" + componentTestDigests["armtlsMesh.image"],
	}
	for name, tc := range map[string]struct {
		args []string
		base bool
	}{
		"components": {base: true},
		"bare metal": {args: bareMetal, base: true},
		"baked":      {args: bakedArgs},
	} {
		t.Run(name, func(t *testing.T) {
			var out string
			if tc.args == nil {
				out = componentRender(t)
			} else {
				var err error
				if out, err = helmTemplate(t, tc.args...); err != nil {
					t.Fatalf("helm template: %v\n%s", err, out)
				}
			}
			sources := map[string]*pkgallowlist.Allowlist{"seed": renderedSeed(t, out)}
			if tc.base {
				base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
				sources["base"] = &base
			}
			containers := renderedComponentContainers(t, out)
			if len(containers) == 0 {
				t.Fatal("no rendered container runs a component image")
			}
			for _, cc := range containers {
				c := cc.container
				argv := effectiveArgv(c)
				if len(c.Command) == 0 {
					argv = append(slices.Clone(cc.image.entrypoint), c.Args...)
				}
				running := func(extra ...string) pkgallowlist.RunningContainer {
					return pkgallowlist.RunningContainer{Digest: cc.digest, Argv: argv, Mounts: []pkgallowlist.ObservedMount{}, Env: launchEnv(t, cc.image.env, c, extra...)}
				}
				for source, al := range sources {
					if source == "base" && cc.workload == "DaemonSet/c8s-volumed-teardown" {
						continue
					}
					index := al.BuildIndex()
					if !index.AdmitsContainer(running()) {
						t.Errorf("%s refuses %s container %s with its launch env", source, cc.workload, c.Name)
					}
					for _, extra := range append(slices.Clone(loaderVariables), "C8S_CDS_SERVICE_HOST", "PATH") {
						value := "/tmp/x"
						if extra == "PATH" {
							value = "/tmp:/usr/bin:/bin"
						}
						if index.AdmitsContainer(running(extra + "=" + value)) {
							t.Errorf("%s admits %s container %s with %s set", source, cc.workload, c.Name, extra)
						}
					}
				}
			}
		})
	}
}

// Every container of a component entry matches env by name, pins PATH to the
// image's value and lists no loader variable.
func TestChartComponentEntriesPinLoaderVariables(t *testing.T) {
	out := componentRender(t)
	seed := renderedSeed(t, out)
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	for source, al := range map[string]*pkgallowlist.Allowlist{"seed": seed, "base": &base} {
		for name, w := range al.Workloads {
			for _, c := range append(slices.Clone(w.InitContainers), w.Containers...) {
				if c.Env.Policy != pkgallowlist.PolicyMatch {
					if strings.HasPrefix(c.Image, "ghcr.io/confidential-dot-ai/nri-image-policy@") || strings.HasPrefix(c.Image, "busybox@") {
						continue
					}
					t.Errorf("%s %s container %q env policy = %q, want match", source, name, c.Command.Argv, c.Env.Policy)
					continue
				}
				if got := c.Env.ExactValues()["PATH"]; got != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
					t.Errorf("%s %s container %q PATH = %q, want the image's, pinned exact", source, name, c.Command.Argv, got)
				}
				for variable := range c.Env.Variables {
					if slices.Contains(loaderVariables, variable) || strings.HasPrefix(variable, "LD_") || strings.HasPrefix(variable, "NGINX_ENVSUBST_") {
						t.Errorf("%s %s container %q lists loader variable %s", source, name, c.Command.Argv, variable)
					}
				}
			}
		}
	}
}

// A component pod runs some of its image's invocations, never all of them:
// the seed entry still names it, so the pod's certificate carries a workload
// identity.
func TestChartComponentEntriesIdentifyPods(t *testing.T) {
	out := componentRender(t)
	seed := renderedSeed(t, out)
	running := map[string][]pkgallowlist.RunningContainer{}
	for _, cc := range renderedComponentContainers(t, out) {
		argv := effectiveArgv(cc.container)
		if len(cc.container.Command) == 0 {
			argv = append(slices.Clone(cc.image.entrypoint), cc.container.Args...)
		}
		key := cc.workload + " " + cc.digest
		running[key] = append(running[key], pkgallowlist.RunningContainer{Digest: cc.digest, Argv: argv, Mounts: []pkgallowlist.ObservedMount{}, Env: launchEnv(t, cc.image.env, cc.container)})
	}
	for key, set := range running {
		name, _, err := seed.MatchWorkload(set)
		if err != nil {
			t.Errorf("MatchWorkload(%s) = %v, want the component entry", key, err)
			continue
		}
		if want := set[0].Digest[len("sha256:") : len("sha256:")+12]; !strings.HasSuffix(name, want) {
			t.Errorf("MatchWorkload(%s) = %q, want the entry of its digest", key, name)
		}
	}
}

// An application pod's injected fetchers are dropped against the seed's
// invocations, so the pod matches its own entry and receives its grant.
func TestChartComponentEntriesReleaseAppSecrets(t *testing.T) {
	seed := renderedSeed(t, componentRender(t))
	const appDigest = "sha256:2222000000000000000000000000000000000000000000000000000000000001"
	app, err := pkgallowlist.ParseWorkloadJSON([]byte(`{"containers":[{"digest":"` + appDigest + `","command":{"policy":"exact","argv":["/serve"]},"args":{"policy":"exact","argv":["--port=80"]}}],"secrets":{"policy":"allow","read":["/app/db"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	seed.Workloads["app"] = *app
	digest := componentTestDigests["image"]
	imageEnv := componentImages(t)["ghcr.io/confidential-dot-ai/c8s-operator"].env
	fieldRef := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}
	sidecar := corev1.Container{Env: []corev1.EnvVar{
		{Name: "C8S_WORKLOAD_ID", Value: "app"},
		{Name: "C8S_POD_NAME", ValueFrom: fieldRef},
		{Name: "C8S_POD_UID", ValueFrom: fieldRef},
		{Name: "HOST_IP", ValueFrom: fieldRef},
	}}
	reported := []workloadclaims.SandboxContainer{{Digest: appDigest, Argv: []string{"/serve", "--port=80"}, Mounts: []pkgallowlist.ObservedMount{}}}
	for _, mode := range []string{"get-cert", "get-secret"} {
		reported = append(reported, workloadclaims.SandboxContainer{Digest: digest, Argv: []string{"/c8s", mode}, Mounts: []pkgallowlist.ObservedMount{}, Env: launchEnv(t, imageEnv, sidecar)})
	}
	name, workload, err := seed.MatchWorkload(secrets.WorkloadContainers(seed, reported))
	if err != nil || name != "app" {
		t.Fatalf("MatchWorkload(app with injected fetchers) = %q, %v, want app", name, err)
	}
	if workload.Secrets == nil || !workload.ArgvPinned() {
		t.Fatalf("app entry releases nothing: secrets %v, argv pinned %v", workload.Secrets, workload.ArgvPinned())
	}
}

// The webhook's sidecars run in application pods, so the chart never renders
// them: build them as mutatePod does (getCertEnv in
// internal/webhook/pod_mutator.go) and check the seed admits each.
func TestChartComponentEntriesAdmitInjectedSidecars(t *testing.T) {
	out := componentRender(t)
	seed := renderedSeed(t, out).BuildIndex()
	digest := componentTestDigests["image"]
	imageEnv := componentImages(t)["ghcr.io/confidential-dot-ai/c8s-operator"].env
	fieldRef := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}
	sidecarEnv := []corev1.EnvVar{
		{Name: "C8S_WORKLOAD_ID", Value: "api"},
		{Name: "C8S_POD_NAME", ValueFrom: fieldRef},
		{Name: "C8S_POD_UID", ValueFrom: fieldRef},
		{Name: "HOST_IP", ValueFrom: fieldRef},
	}
	for _, c := range []corev1.Container{
		{Name: "c8s-cert", Args: []string{"get-cert", "--san=api"}, Env: sidecarEnv},
		{Name: "c8s-secret", Args: []string{"get-secret", "--secret=DB=/a/db"}, Env: sidecarEnv},
		{Name: "c8s-volume", Args: []string{"get-volume", "--volume=data"}, Env: sidecarEnv},
		{Name: "c8s-cert-wait", Command: []string{"/c8s", "probe-file", "--wait", "/etc/c8s/certs/tls.crt"}},
	} {
		argv := effectiveArgv(c)
		if len(c.Command) == 0 {
			argv = append([]string{"/c8s"}, c.Args...)
		}
		r := pkgallowlist.RunningContainer{Digest: digest, Argv: argv, Mounts: []pkgallowlist.ObservedMount{}, Env: launchEnv(t, imageEnv, c)}
		if !seed.AdmitsContainer(r) {
			t.Errorf("seed refuses injected %s with its launch env", c.Name)
		}
		r.Env = launchEnv(t, imageEnv, c, "LD_PRELOAD=/tmp/x.so")
		if seed.AdmitsContainer(r) {
			t.Errorf("seed admits injected %s with LD_PRELOAD set", c.Name)
		}
	}
}

// The images built here set no ENV of their own beyond what imageEnv
// declares; the rest comes from the pinned base image.
func TestChartComponentImageEnvsCoverDockerfiles(t *testing.T) {
	images := componentImages(t)
	for repository, dockerfile := range map[string]string{
		"ghcr.io/confidential-dot-ai/c8s-operator": "../../cmd/c8s/Dockerfile",
		"ghcr.io/confidential-dot-ai/cds":          "../../cmd/cds/Dockerfile",
		"ghcr.io/confidential-dot-ai/armtls-mesh":  "../../cmd/armtls-mesh/Dockerfile",
		"ghcr.io/confidential-dot-ai/volumed":      "../../cmd/volumed/Dockerfile",
	} {
		raw, err := os.ReadFile(dockerfile)
		if err != nil {
			t.Fatalf("read %s: %v", dockerfile, err)
		}
		if _, ok := images[repository].env["PATH"]; !ok {
			t.Errorf("%s imageEnv lacks PATH", repository)
		}
		for _, m := range regexp.MustCompile(`(?m)^ENV\s+([A-Za-z_][A-Za-z0-9_]*)[=\s]`).FindAllSubmatch(raw, -1) {
			if _, ok := images[repository].env[string(m[1])]; !ok {
				t.Errorf("%s sets ENV %s, which %s imageEnv lacks", dockerfile, m[1], repository)
			}
		}
	}
}

// The kubelet sets its API-server variables over the image's, so an image
// that declares one launches with the kubelet's value, which the entry must
// pin.
func TestChartComponentEntriesPinKubeletOverImageEnv(t *testing.T) {
	out := componentRender(t, "--set", "router.nginx.imageEnv.KUBERNETES_SERVICE_PORT=9999", "--set", "router.nginx.imageEnv.HOSTNAME=nginx")
	seed := renderedSeed(t, out).BuildIndex()
	checked := false
	for _, cc := range renderedComponentContainers(t, out) {
		if cc.image.env["NGINX_VERSION"] == "" {
			continue
		}
		checked = true
		imageEnv := maps.Clone(cc.image.env)
		imageEnv["KUBERNETES_SERVICE_PORT"] = "9999"
		imageEnv["HOSTNAME"] = "nginx"
		argv := effectiveArgv(cc.container)
		if len(cc.container.Command) == 0 {
			argv = append(slices.Clone(cc.image.entrypoint), cc.container.Args...)
		}
		r := pkgallowlist.RunningContainer{Digest: cc.digest, Argv: argv, Mounts: []pkgallowlist.ObservedMount{}, Env: launchEnv(t, imageEnv, cc.container)}
		if !seed.AdmitsContainer(r) {
			t.Errorf("seed refuses %s container %s launching with the kubelet's KUBERNETES_SERVICE_PORT over the image's", cc.workload, cc.container.Name)
		}
	}
	if !checked {
		t.Fatal("no rendered container runs the nginx image")
	}
}
