package main

import (
	"os"
	"testing"

	"sigs.k8s.io/yaml"
)

// workerRoleConfig is the worker role's hand-written containerd config.
const workerRoleConfig = "../mkosi.extra/usr/lib/c8s/worker-runtime/containerd.toml"

// workerRoleDifferences lists every key on which the worker role's config may
// differ from the pod role's, and why. The pod role's config follows RKE2's
// base (TestPodRoleConfigFollowsRKE2Base), so the worker's does too.
var workerRoleDifferences = map[string]string{
	"plugins/io.containerd.cri.v1.runtime/cni/bin_dirs": "the cluster's Cilium installs its plugin on the default dir, " +
		"as RKE2's bundled Cilium does on an agent",
	"plugins/io.containerd.cri.v1.runtime/cni/conf_dir": "the cluster's Cilium writes its conflist on the default dir",
}

func TestWorkerRoleConfigFollowsPodRole(t *testing.T) {
	pod, err := os.ReadFile(podRoleConfig)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := os.ReadFile(workerRoleConfig)
	if err != nil {
		t.Fatal(err)
	}
	podLeaves := flattenTOML(t, podRoleConfig, pod)
	workerLeaves := flattenTOML(t, workerRoleConfig, worker)
	for _, path := range diffLeaves(podLeaves, workerLeaves) {
		if _, ok := workerRoleDifferences[path]; ok {
			continue
		}
		t.Errorf("%s: the pod role has %s, the worker role has %s; follow the pod role or add the key to workerRoleDifferences with a reason",
			path, show(podLeaves, path), show(workerLeaves, path))
	}
	if got := workerLeaves["plugins/io.containerd.cri.v1.runtime/cni/conf_dir"]; got != "/etc/cni/net.d" {
		t.Fatalf("worker CNI directory = %v, want the default the cluster's CNI writes", got)
	}
}

// The worker's API server is outside the trust boundary, so nothing it can
// ask of the kubelet may reach into a container: the debugging handlers are
// off, and every request is authenticated and authorized.
func TestWorkerKubeletClosesTheAPIServersReach(t *testing.T) {
	data, err := os.ReadFile("../mkosi.extra/usr/lib/c8s/worker-runtime/kubelet.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		EnableDebuggingHandlers *bool `json:"enableDebuggingHandlers"`
		Authentication          struct {
			Anonymous struct{ Enabled *bool } `json:"anonymous"`
			Webhook   struct{ Enabled *bool } `json:"webhook"`
		} `json:"authentication"`
		Authorization struct{ Mode string } `json:"authorization"`
		ReadOnlyPort  *int                  `json:"readOnlyPort"`
		StaticPodPath *string               `json:"staticPodPath"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.EnableDebuggingHandlers == nil || *config.EnableDebuggingHandlers {
		t.Error("worker kubelet must turn its debugging handlers off")
	}
	if a := config.Authentication.Anonymous.Enabled; a == nil || *a {
		t.Error("worker kubelet must refuse anonymous requests")
	}
	if w := config.Authentication.Webhook.Enabled; w == nil || !*w || config.Authorization.Mode != "Webhook" {
		t.Error("worker kubelet must authenticate and authorize every request through the API server")
	}
	if config.ReadOnlyPort == nil || *config.ReadOnlyPort != 0 {
		t.Error("worker kubelet must close its read-only port")
	}
	if config.StaticPodPath == nil || *config.StaticPodPath != "" {
		t.Error("worker kubelet must run no static pods")
	}
}
