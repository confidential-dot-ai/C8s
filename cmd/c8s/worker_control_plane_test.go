//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/worker"
	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

const (
	routerDeploymentKey = "Deployment/c8s-router/c8s-router"
	volumedDaemonSetKey = "DaemonSet/c8s-system/c8s-volumed"
)

// workerChartDir is the c8s-worker chart in the repository layout.
var workerChartDir = filepath.Join("..", "..", "charts", "worker")

// workerRenderConfig is the worker image build's render configuration.
func workerRenderConfig() nodeImageRenderConfig {
	return nodeImageRenderConfig{
		platform:                  "sev-snp",
		kubeVersion:               "v1.36.6",
		chartDir:                  workerChartDir,
		imageDigest:               testDigest,
		imageRepository:           "registry.example.com/c8s-operator",
		armtlsMeshImageDigest:     nodeImageTestMeshDigest,
		armtlsMeshImageRepository: "registry.example.com/armtls-mesh",
		volumedImageDigest:        nodeImageTestVolumedDigest,
		volumedImageRepository:    "registry.example.com/volumed",
	}
}

// renderTestWorkerCluster is worker control-plane render's cluster.yaml for
// the worker image build's configuration on platform.
func renderTestWorkerCluster(t *testing.T, platform string) map[string]unstructured.Unstructured {
	t.Helper()
	cfg := workerRenderConfig()
	cfg.platform = platform
	doc := &worker.Document{Kubernetes: worker.Kubernetes{ClusterDNS: "10.53.0.10"}}
	cluster, err := renderWorkerCluster(context.Background(), cfg, "127.0.0.1", false, doc)
	if err != nil {
		t.Fatal(err)
	}
	return renderedObjects(t, cluster)
}

// renderedObjects decodes a multi-document render.
func renderedObjects(t *testing.T, data []byte) map[string]unstructured.Unstructured {
	t.Helper()
	objects := map[string]unstructured.Unstructured{}
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var object unstructured.Unstructured
		if err := dec.Decode(&object.Object); errors.Is(err, io.EOF) {
			return objects
		} else if err != nil {
			t.Fatal(err)
		}
		if len(object.Object) > 0 {
			objects[strings.Join([]string{object.GetKind(), object.GetNamespace(), object.GetName()}, "/")] = object
		}
	}
}

// routerDeployment is the router Deployment of a render.
func routerDeployment(t *testing.T, objects map[string]unstructured.Unstructured) appsv1.Deployment {
	t.Helper()
	var d appsv1.Deployment
	data, err := yaml.Marshal(objects[routerDeploymentKey].Object)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &d); err != nil || len(d.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("no router Deployment: %v", err)
	}
	return d
}

func TestWorkerClusterHoldsTheWorkerChartsClusterObjects(t *testing.T) {
	for _, platform := range []string{"sev-snp", "tdx"} {
		objects := renderTestWorkerCluster(t, platform)
		if got := slices.Sorted(maps.Keys(objects)); !slices.Equal(got, workerClusterObjects) {
			t.Fatalf("%s: objects = %v, want %v", platform, got, workerClusterObjects)
		}
		for _, key := range []string{"MutatingWebhookConfiguration//c8s-pod-injector", "ValidatingWebhookConfiguration//c8s-pod-validator"} {
			webhooks, _, _ := unstructured.NestedSlice(objects[key].Object, "webhooks")
			for _, hook := range webhooks {
				config := hook.(map[string]any)["clientConfig"].(map[string]any)
				if _, service := config["service"]; service || !strings.HasPrefix(config["url"].(string), "https://127.0.0.1:9443/") {
					t.Fatalf("%s clientConfig = %v, want the operator's host alone", key, config)
				}
			}
		}
		subjects, _, _ := unstructured.NestedSlice(objects["ClusterRoleBinding//c8s-operator"].Object, "subjects")
		operator := map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": operatorUser}
		if len(subjects) != 1 || !maps.Equal(subjects[0].(map[string]any), operator) {
			t.Fatalf("operator binding subjects = %v, want the user %s alone", subjects, operatorUser)
		}
		if ip, _, _ := unstructured.NestedString(objects["Service/kube-system/kube-dns"].Object, "spec", "clusterIP"); ip != "10.53.0.10" {
			t.Fatalf("kube-dns clusterIP = %q, want the document's clusterDNS", ip)
		}
		pod := routerDeployment(t, objects).Spec.Template.Spec
		for _, c := range slices.Concat(pod.InitContainers, pod.Containers) {
			if c.ImagePullPolicy != "IfNotPresent" {
				t.Fatalf("router container %s pulls %s, want IfNotPresent: a worker bakes none of its images", c.Name, c.ImagePullPolicy)
			}
		}
		if !maps.Equal(pod.NodeSelector, map[string]string{"confidential.ai/router-eligible": "true"}) {
			t.Fatalf("router nodeSelector = %v, want current Trust Authority eligibility", pod.NodeSelector)
		}
	}
}

// --pod-cvm-provider adds the provider's grants, bound to the operator's user.
func TestWorkerClusterGrantsThePodCVMProvider(t *testing.T) {
	doc := &worker.Document{Kubernetes: worker.Kubernetes{ClusterDNS: "10.53.0.10"}}
	cluster, err := renderWorkerCluster(context.Background(), workerRenderConfig(), "127.0.0.1", true, doc)
	if err != nil {
		t.Fatal(err)
	}
	objects := renderedObjects(t, cluster)
	for _, key := range workerClusterPodCVMProviderObjects {
		if _, ok := objects[key]; !ok {
			t.Fatalf("no %s", key)
		}
	}
	operator := map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": operatorUser}
	for _, key := range []string{"ClusterRoleBinding//c8s-operator-pod-cvm", "RoleBinding/c8s-system/c8s-operator-pod-cvm"} {
		subjects, _, _ := unstructured.NestedSlice(objects[key].Object, "subjects")
		if len(subjects) != 1 || !maps.Equal(subjects[0].(map[string]any), operator) {
			t.Fatalf("%s subjects = %v, want the user %s alone", key, subjects, operatorUser)
		}
	}
	rules, _, _ := unstructured.NestedSlice(objects["ClusterRole//c8s-operator-pod-cvm"].Object, "rules")
	for _, want := range []string{"pods/status", "nodes", "events.k8s.io"} {
		if !strings.Contains(fmt.Sprint(rules), want) {
			t.Fatalf("provider ClusterRole lacks %s: %v", want, rules)
		}
	}
}

// routerEntryName is the allowlist entry the router pod's c8s-cert sidecar is
// pinned to, which is the entry its launch has to match.
func routerEntryName(t *testing.T, objects map[string]unstructured.Unstructured) string {
	t.Helper()
	for _, container := range routerDeployment(t, objects).Spec.Template.Spec.InitContainers {
		for _, arg := range container.Args {
			if name, pinned := strings.CutPrefix(arg, "--expected-workload="); pinned {
				return name
			}
		}
	}
	t.Fatal("no container of the router pod names its allowlist entry")
	return ""
}

// The router a cluster of workers holds is the one the worker image's seed,
// and so its floor, pins.
func TestWorkerClusterRouterIsTheImagesSeededRouter(t *testing.T) {
	for _, platform := range []string{"sev-snp", "tdx"} {
		cfg := workerRenderConfig()
		cfg.platform = platform
		cfg.outputDir = t.TempDir()
		if err := renderNodeImage(context.Background(), cfg, io.Discard); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(cfg.outputDir, "allowlist-seed.json"))
		if err != nil {
			t.Fatal(err)
		}
		seed, err := pkgallowlist.ParseJSON(data)
		if err != nil {
			t.Fatal(err)
		}
		name := routerEntryName(t, renderTestWorkerCluster(t, platform))
		if _, seeded := seed.Workloads[name]; !seeded {
			t.Errorf("%s: the cluster's router is pinned to %s, which the image's seed does not hold", platform, name)
		}
	}
}

// volumedDaemonSet is the volumed DaemonSet of a render.
func volumedDaemonSet(t *testing.T, objects map[string]unstructured.Unstructured) appsv1.DaemonSet {
	t.Helper()
	var ds appsv1.DaemonSet
	data, err := yaml.Marshal(objects[volumedDaemonSetKey].Object)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &ds); err != nil || len(ds.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("no volumed DaemonSet of one container: %v", err)
	}
	return ds
}

// volumed opens encrypted volumes for the pods on its worker, so the DaemonSet
// runs one privileged root container per worker in the host PID namespace,
// replacing it one worker at a time.
func TestWorkerClusterVolumedRunsOnEveryWorker(t *testing.T) {
	ds := volumedDaemonSet(t, renderTestWorkerCluster(t, "sev-snp"))
	if ds.Spec.UpdateStrategy.Type != appsv1.RollingUpdateDaemonSetStrategyType {
		t.Errorf("update strategy = %q, want a rolling update", ds.Spec.UpdateStrategy.Type)
	}
	pod := ds.Spec.Template.Spec
	if !pod.HostPID {
		t.Error("the pod does not share the host PID namespace, so a caller's peer credentials resolve to 0")
	}
	if !pod.HostNetwork {
		t.Error("the pod is on the pod network, where the enforcer holds it for a mesh endpoint it does not run")
	}
	if pod.NodeSelector["confidential.ai/worker"] != "true" {
		t.Errorf("node selector = %v, want the workers alone: a control-plane node blocks the rollout", pod.NodeSelector)
	}
	if pod.ServiceAccountName == "" || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Errorf("the pod runs as %q with a mounted token, want its own account and none", pod.ServiceAccountName)
	}
	c := pod.Containers[0]
	if want := "registry.example.com/volumed@" + nodeImageTestVolumedDigest; c.Image != want {
		t.Errorf("image = %q, want %q, the image carrying cryptsetup", c.Image, want)
	}
	security := c.SecurityContext
	if security == nil || security.Privileged == nil || !*security.Privileged ||
		security.RunAsUser == nil || *security.RunAsUser != 0 {
		t.Errorf("container security context = %+v, want privileged and root", security)
	}
	wantArgs := []string{
		"--socket-dir=" + hostNriRuntimeDir,
		"--state-dir=/var/lib/c8s/volumed",
		"--kubelet-root=/var/lib/kubelet",
	}
	if !slices.Equal(c.Args, wantArgs) {
		t.Errorf("args = %v, want %v", c.Args, wantArgs)
	}
	hostPaths := map[string]string{}
	for _, v := range pod.Volumes {
		if v.HostPath == nil {
			t.Fatalf("volume %s is no host path: volumed acts on the node alone", v.Name)
		}
		hostPaths[v.Name] = v.HostPath.Path
	}
	mounted := map[string]string{}
	for _, m := range c.VolumeMounts {
		mounted[m.MountPath] = hostPaths[m.Name]
		if m.MountPath == "/var/lib/kubelet" &&
			(m.MountPropagation == nil || *m.MountPropagation != corev1.MountPropagationBidirectional) {
			t.Error("the kubelet directory is not mounted bidirectionally, so a mount made here never reaches the pod")
		}
	}
	want := map[string]string{
		"/var/lib/kubelet":     "/var/lib/kubelet",
		"/var/lib/c8s/volumed": "/var/lib/c8s/volumed",
		"/dev":                 "/dev",
		"/sys":                 "/sys",
		"/sys/fs/cgroup":       "/sys/fs/cgroup",
		hostNriRuntimeDir:      hostNriRuntimeDir,
	}
	if !maps.Equal(mounted, want) {
		t.Errorf("mounts = %v, want %v", mounted, want)
	}
}

// The seed's entry for the volumed DaemonSet is a launch a component set can
// publish as a node service: one container with its command, args, env and
// mounts pinned.
func TestWorkerSeedsVolumedAsANodeService(t *testing.T) {
	cfg := workerRenderConfig()
	cfg.outputDir = t.TempDir()
	if err := renderNodeImage(context.Background(), cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(cfg.outputDir, "allowlist-seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	name, entry := seededEntry(t, seed, "c8s-volumed-")
	entry.NodeService = true
	set, err := json.Marshal(pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{},
		Components: map[string]pkgallowlist.ComponentSet{
			nodeImageTestSetVersion: {Entries: map[string]pkgallowlist.Workload{name: entry}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	published, err := pkgallowlist.ParseJSON(set)
	if err != nil {
		t.Fatalf("the seed's %s entry is no node service: %v", name, err)
	}
	if !published.Components[nodeImageTestSetVersion].Entries[name].NodeService {
		t.Error("the node-service mark was lost")
	}
}

// seededEntry is the seed's one entry named with prefix.
func seededEntry(t *testing.T, seed *pkgallowlist.Allowlist, prefix string) (string, pkgallowlist.Workload) {
	t.Helper()
	var names []string
	for name := range seed.Workloads {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		t.Fatalf("the seed holds the %s* entries %v, want one", prefix, names)
	}
	return names[0], seed.Workloads[names[0]]
}
