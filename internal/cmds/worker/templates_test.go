package worker

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

// imageTree is the worker profile's tree, as the image holds it.
const imageTree = "../../../images/node-guest/worker/mkosi.extra"

// The worker image's static pods each build a floor entry, render with this
// boot's values, and mount only files the image holds from under
// /usr/lib/c8s/worker.
func TestWorkerImageStaticPods(t *testing.T) {
	templates, err := readTemplates(filepath.Join(imageTree, staticPodTemplates))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := slices.Sorted(maps.Keys(templates)), []string{"cilium.yaml"}; !slices.Equal(got, want) {
		t.Fatalf("templates = %v, want %v", got, want)
	}
	for file, data := range templates {
		if _, _, err := staticPodEntry(data); err != nil {
			t.Errorf("%s builds no floor entry: %v", file, err)
		}
	}
	root := t.TempDir()
	if err := os.CopyFS(filepath.Join(root, staticPodTemplates), os.DirFS(filepath.Join(imageTree, staticPodTemplates))); err != nil {
		t.Fatal(err)
	}
	pods, err := staticPods(root, map[string]string{nodeservices.NodeNamePlaceholder: "n-0123456789abcdef", nodeservices.PodCIDRPlaceholder: "10.42.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range pods {
		pod, err := decodeStaticPod(rendered.Data)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range pod.Spec.Volumes {
			if v.HostPath == nil || !strings.HasPrefix(v.HostPath.Path, "/usr/lib/c8s/worker/") {
				continue
			}
			if _, err := os.Stat(filepath.Join(imageTree, v.HostPath.Path)); err != nil {
				t.Errorf("%s mounts %s, which the image does not hold: %v", rendered.Name, v.HostPath.Path, err)
			}
		}
	}
}

// Cilium ignores a configuration key it does not read, and some default on, so
// the worker's measured configuration states each one the worker rests on: no
// configuration, secrets or L7 proxy from the control plane, no listener on a
// node address beyond its own, kube-proxy left to route Services, and the
// datapath the mesh expects.
func TestWorkerCiliumConfiguration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(imageTree, "usr/lib/c8s/worker/cilium/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]string
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"enable-dynamic-config":           "false",
		"enable-policy-secrets-sync":      "false",
		"enable-l7-proxy":                 "false",
		"enable-hubble":                   "false",
		"enable-health-checking":          "false",
		"enable-endpoint-health-checking": "false",
		"kube-proxy-replacement":          "false",
		"bpf-lb-sock":                     "false",
		"datapath-mode":                   "veth",
		"routing-mode":                    "tunnel",
		"tunnel-protocol":                 "vxlan",
		"tunnel-port":                     "8473",
		"ipam":                            "kubernetes",
		"k8s-require-ipv4-pod-cidr":       "true",
		"k8s-kubeconfig-path":             "/var/lib/kubelet/kubeconfig",
	} {
		if got, ok := config[key]; !ok || got != want {
			t.Errorf("%s = %q (set %v), want %q", key, got, ok, want)
		}
	}
	for _, listener := range []string{"proxy-prometheus-port", "prometheus-serve-addr", "hubble-listen-address", "hubble-metrics-server"} {
		if value, ok := config[listener]; ok {
			t.Errorf("%s = %q opens a listener on the node", listener, value)
		}
	}
}
