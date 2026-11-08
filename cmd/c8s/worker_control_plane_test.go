//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const routerDeploymentKey = "Deployment/c8s-router/c8s-router"

// workerChartDir is the c8s-worker chart in the repository layout.
var workerChartDir = filepath.Join("..", "..", "internal", "helmchart", "worker")

// workerRenderConfig is the worker image build's render configuration.
func workerRenderConfig() nodeImageRenderConfig {
	return nodeImageRenderConfig{
		platform:                  "sev-snp",
		kubeVersion:               "v1.36.4",
		chartDir:                  workerChartDir,
		imageDigest:               testDigest,
		imageRepository:           "registry.example.com/c8s-operator",
		armtlsMeshImageDigest:     nodeImageTestMeshDigest,
		armtlsMeshImageRepository: "registry.example.com/armtls-mesh",
	}
}

// renderTestWorkerCluster is worker control-plane render's cluster.yaml for
// the worker image build's configuration on platform.
func renderTestWorkerCluster(t *testing.T, platform string) map[string]unstructured.Unstructured {
	t.Helper()
	cfg := workerRenderConfig()
	cfg.platform = platform
	doc := &worker.Document{Kubernetes: worker.Kubernetes{ClusterDNS: "10.53.0.10"}}
	cluster, err := renderWorkerCluster(context.Background(), cfg, "127.0.0.1", doc)
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

// A cluster of workers holds the worker chart's cluster objects: the operator's
// grants bound to its user alone, its webhooks at its host, kube-dns at the
// document's clusterDNS, and a router that pulls its images and runs on any
// worker.
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
		if len(pod.NodeSelector) > 0 {
			t.Fatalf("router nodeSelector = %v, which no worker carries", pod.NodeSelector)
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
		if err := renderNodeImage(context.Background(), cfg); err != nil {
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
