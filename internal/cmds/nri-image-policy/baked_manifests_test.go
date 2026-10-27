package nriimagepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	corev1 "k8s.io/api/core/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// nodeImageDir holds the manifests the node image bakes: the optional
// local-path provisioner under local-path/, the rest under
// mkosi.extra/var/lib/rancher/rke2/server/manifests/.
const nodeImageDir = "../../../node-guest-image/c8s/"

// The node image's own manifests run under base entries that pin their whole
// launch, environment included: each container, launched as the kubelet and
// containerd launch it, is admitted, and the same launch with its environment
// changed is refused.
func TestNodeImageBaseAdmitsTheBakedManifests(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	imageEnv := bakedManifestImageEnv(t)
	for _, manifest := range []string{"local-path/local-path-storage.yaml", "mkosi.extra/var/lib/rancher/rke2/server/manifests/nvidia-device-plugin.yaml"} {
		for _, w := range bakedWorkloads(t, manifest) {
			for _, c := range w.Spec.Template.Spec.Containers {
				for _, tc := range []struct {
					name     string
					change   map[string]string
					admitted bool
				}{
					{"as the manifest launches it", nil, true},
					{"with a preloaded library", map[string]string{"LD_PRELOAD": "/mnt/c8s-data/x.so"}, false},
					{"with another PATH", map[string]string{"PATH": "/mnt/c8s-data"}, false},
				} {
					t.Run(w.Metadata.Name+"/"+c.Name+"/"+tc.name, func(t *testing.T) {
						p := newTestPlugin(cfg)
						p.mountStorage = fixedStorage(allowlist.MountEncrypted)
						p.SetReady()
						pod := makePod(w.Metadata.Namespace, w.Metadata.Name)
						pod.Uid = "5a1d-pod"
						if p.mesh.hosts(pod) {
							t.Fatalf("namespace %s is covered by the mesh gate", pod.Namespace)
						}
						env := launchEnv(t, pod, c, imageEnv[digestOf(c.Image)])
						maps.Copy(env, tc.change)
						ctr := bakedLaunch(t, pod, w.Spec.Template.Spec, c, env)
						_, _, err := createAndStart(p, t.Context(), pod, ctr)
						if (err == nil) != tc.admitted {
							t.Fatalf("admission error = %v, want admitted %v", err, tc.admitted)
						}
					})
				}
			}
		}
	}
}

// bakedWorkload is the part of a baked Deployment or DaemonSet these tests
// read.
type bakedWorkload struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Spec corev1.PodSpec `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

// bakedWorkloads are the Deployments and DaemonSets of a baked manifest.
func bakedWorkloads(t *testing.T, manifest string) []bakedWorkload {
	t.Helper()
	data, err := os.ReadFile(nodeImageDir + manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var workloads []bakedWorkload
	for {
		var w bakedWorkload
		err := decoder.Decode(&w)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if w.Kind == "Deployment" || w.Kind == "DaemonSet" {
			workloads = append(workloads, w)
		}
	}
	if len(workloads) == 0 {
		t.Fatalf("%s runs no workload", manifest)
	}
	return workloads
}

// bakedManifestImageEnv are the environments the pulled images' configs set,
// by digest (`crane config` of each digest the manifests pin).
func bakedManifestImageEnv(t *testing.T) map[string][]string {
	t.Helper()
	data, err := os.ReadFile("testdata/baked-manifest-images.json")
	if err != nil {
		t.Fatal(err)
	}
	var images map[string]struct {
		Env []string `json:"env"`
	}
	if err := json.Unmarshal(data, &images); err != nil {
		t.Fatal(err)
	}
	env := make(map[string][]string, len(images))
	for digest, image := range images {
		env[digest] = image.Env
	}
	return env
}

func digestOf(image string) string {
	_, digest, _ := strings.Cut(image, "@")
	return digest
}

// launchEnv is the environment c starts with: containerd's HOSTNAME, the
// image's variables, the kubelet's for the default namespace's kubernetes
// Service, then the manifest's, each layer overriding the one before.
func launchEnv(t *testing.T, pod *api.PodSandbox, c corev1.Container, image []string) map[string]string {
	t.Helper()
	imageEnv := map[string]string{}
	for _, variable := range image {
		name, value, _ := strings.Cut(variable, "=")
		imageEnv[name] = value
	}
	manifestEnv := map[string]string{}
	for _, e := range c.Env {
		switch {
		case e.ValueFrom == nil:
			manifestEnv[e.Name] = e.Value
		case e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "metadata.namespace":
			manifestEnv[e.Name] = pod.Namespace
		default:
			t.Fatalf("%s takes %s from a source this test does not resolve", c.Name, e.Name)
		}
	}
	env := map[string]string{}
	for _, layer := range []map[string]string{{"HOSTNAME": pod.Name}, imageEnv, kubernetesServiceEnv, manifestEnv} {
		maps.Copy(env, layer)
	}
	return env
}

// kubernetesServiceEnv is what the kubelet sets for the default namespace's
// kubernetes Service in every container, service links on or off.
var kubernetesServiceEnv = map[string]string{
	"KUBERNETES_SERVICE_HOST":       "10.53.0.1",
	"KUBERNETES_SERVICE_PORT":       "443",
	"KUBERNETES_SERVICE_PORT_HTTPS": "443",
	"KUBERNETES_PORT":               "tcp://10.53.0.1:443",
	"KUBERNETES_PORT_443_TCP":       "tcp://10.53.0.1:443",
	"KUBERNETES_PORT_443_TCP_ADDR":  "10.53.0.1",
	"KUBERNETES_PORT_443_TCP_PORT":  "443",
	"KUBERNETES_PORT_443_TCP_PROTO": "tcp",
}

// bakedLaunch is the container the runtime asks admission about: its argv,
// env, and the binds the kubelet stages for its volumes and service account
// token.
func bakedLaunch(t *testing.T, pod *api.PodSandbox, spec corev1.PodSpec, c corev1.Container, env map[string]string) *api.Container {
	t.Helper()
	ctr := makeCtrWithImageArgs(pod.Id, c.Name, c.Image, slices.Concat(c.Command, c.Args))
	for _, name := range slices.Sorted(maps.Keys(env)) {
		ctr.Env = append(ctr.Env, name+"="+env[name])
	}
	volumes := kubeletRoot + "/pods/" + pod.Uid + "/volumes/"
	ctr.Mounts = append(ctr.Mounts, kubeletBind(volumes+projectedPlugin+"/"+serviceAccountTokenVolume, serviceAccountDestination, true))
	for _, m := range c.VolumeMounts {
		i := slices.IndexFunc(spec.Volumes, func(v corev1.Volume) bool { return v.Name == m.Name })
		if i < 0 {
			t.Fatalf("%s mounts missing volume %s", c.Name, m.Name)
		}
		var source string
		switch v := spec.Volumes[i]; {
		case v.HostPath != nil:
			source = v.HostPath.Path
		case v.ConfigMap != nil:
			source = volumes + "kubernetes.io~configmap/" + v.Name
		default:
			t.Fatalf("%s mounts volume %s of a kind this test does not stage", c.Name, m.Name)
		}
		ctr.Mounts = append(ctr.Mounts, kubeletBind(source, m.MountPath, m.ReadOnly))
	}
	return ctr
}

// serviceAccountTokenVolume is the projected volume the kubelet adds for a
// pod's service account token, named as the kubelet names it.
const serviceAccountTokenVolume = "kube-api-access-5a1d"

// kubeletBind is a bind the kubelet asks the runtime for.
func kubeletBind(source, destination string, readOnly bool) *api.Mount {
	access := "rw"
	if readOnly {
		access = "ro"
	}
	return &api.Mount{Source: source, Destination: destination, Type: "bind", Options: []string{"rbind", "rprivate", access}}
}
