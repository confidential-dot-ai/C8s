//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
)

// workerRenderConfig is the worker image build's render configuration.
func workerRenderConfig() nodeImageRenderConfig {
	return nodeImageRenderConfig{
		platform:                  "sev-snp",
		kubeVersion:               "v1.36.4",
		chartDir:                  filepath.Join("..", "..", "internal", "helmchart", "c8s"),
		imageDigest:               testDigest,
		imageRepository:           "registry.example.com/c8s-operator",
		armtlsMeshImageDigest:     nodeImageTestMeshDigest,
		armtlsMeshImageRepository: "registry.example.com/armtls-mesh",
		routerImageDigest:         nodeImageTestRouterDigest,
		routerImageRepository:     "registry.example.com/nginx",
	}
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

// routerLaunch is what the worker image's floor pins of the router: its
// containers, pulling alike, and the volumes they mount.
func routerLaunch(t *testing.T, objects map[string]unstructured.Unstructured) any {
	t.Helper()
	var d appsv1.Deployment
	data, err := yaml.Marshal(objects["Deployment/c8s-router/c8s-router"].Object)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &d); err != nil || len(d.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("no router Deployment: %v", err)
	}
	spec := d.Spec.Template.Spec
	for _, containers := range [][]corev1.Container{spec.InitContainers, spec.Containers} {
		for i := range containers {
			containers[i].ImagePullPolicy = ""
		}
	}
	return []any{spec.InitContainers, spec.Containers, spec.Volumes}
}

// A cluster of workers holds the chart's objects less the operator's own, the
// webhooks at the operator's host and its grants bound to its user, the worker
// objects with kube-dns at the document's clusterDNS, and the router the
// worker image's floor pins, pulled rather than baked, on any worker.
func TestWorkerClusterHoldsTheChartForWorkers(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	cfg := workerRenderConfig()
	doc := &worker.Document{Kubernetes: worker.Kubernetes{ClusterDNS: "10.53.0.10"}}
	cluster, err := renderWorkerCluster(context.Background(), cfg, "127.0.0.1", doc)
	if err != nil {
		t.Fatal(err)
	}
	objects := renderedObjects(t, cluster)
	want := append([]string{"Namespace//c8s-system"}, workerClusterKeeps...)
	want = append(want,
		"ClusterRole//c8s-worker-cilium", "ClusterRoleBinding//c8s-worker-cilium", "ClusterRoleBinding//c8s-worker-kube-proxy",
		"ClusterRole//c8s-worker-cilium-operator", "ClusterRoleBinding//c8s-worker-cilium-operator",
		"Role/kube-system/c8s-worker-cilium-operator-lease", "RoleBinding/kube-system/c8s-worker-cilium-operator-lease",
		"Service/kube-system/kube-dns",
	)
	got := make([]string, 0, len(objects))
	for key := range objects {
		got = append(got, key)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("objects = %v, want %v", got, want)
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
	if len(subjects) != 1 || subjects[0].(map[string]any)["kind"] != "User" || subjects[0].(map[string]any)["name"] != operatorUser {
		t.Fatalf("operator binding subjects = %v, want the user %s alone", subjects, operatorUser)
	}
	if ip, _, _ := unstructured.NestedString(objects["Service/kube-system/kube-dns"].Object, "spec", "clusterIP"); ip != "10.53.0.10" {
		t.Fatalf("kube-dns clusterIP = %q, want the document's clusterDNS", ip)
	}
	containers, _, _ := unstructured.NestedSlice(objects["Deployment/c8s-router/c8s-router"].Object, "spec", "template", "spec", "containers")
	for _, c := range containers {
		if policy := c.(map[string]any)["imagePullPolicy"]; policy != "IfNotPresent" {
			t.Fatalf("router container %v pulls %v, want IfNotPresent: a worker bakes none of its images", c.(map[string]any)["name"], policy)
		}
	}
	image, err := renderNodeImageChart(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(routerLaunch(t, objects), routerLaunch(t, renderedObjects(t, image))) {
		t.Fatal("the router differs from the one the worker image's floor pins")
	}
	if selector, _, _ := unstructured.NestedMap(objects["Deployment/c8s-router/c8s-router"].Object, "spec", "template", "spec", "nodeSelector"); len(selector) > 0 {
		t.Fatalf("router nodeSelector = %v, which no worker carries", selector)
	}
}

// An object the chart renders that a cluster of workers neither holds nor
// leaves out, or one it holds that the chart no longer renders, fails.
func TestWorkerClusterObjectsRefuseAnUnplacedObject(t *testing.T) {
	surprise := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: surprise, namespace: c8s-system}\n"
	if _, err := workerClusterObjects([]byte(surprise), "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "neither holds nor leaves out") {
		t.Fatalf("err = %v, want the unplaced object refused", err)
	}
	if _, err := workerClusterObjects(nil, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "the chart rendered no") {
		t.Fatalf("err = %v, want a missing object refused", err)
	}
}

// The operator's binding is rebound to its user only from the operator's own
// service account.
func TestWorkerClusterRebindsOnlyTheOperatorsAccount(t *testing.T) {
	for _, subjects := range [][]any{
		{map[string]any{"kind": "Group", "name": "system:authenticated"}},
		{map[string]any{"kind": "ServiceAccount", "name": operatorUser, "namespace": nodeImageNamespace}, map[string]any{"kind": "Group", "name": "system:nodes"}},
	} {
		binding := unstructured.Unstructured{Object: map[string]any{"kind": "ClusterRoleBinding", "subjects": subjects}}
		if err := forWorkerCluster(&binding, "ClusterRoleBinding//c8s-operator", "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "not the operator's service account alone") {
			t.Fatalf("subjects %v: err = %v, want them refused", subjects, err)
		}
	}
}
