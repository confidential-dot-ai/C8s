//go:build !c8s_node

package main

import (
	"bytes"
	"context"
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

	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const (
	routerDeploymentKey   = "Deployment/c8s-router/c8s-router"
	operatorDeploymentKey = "Deployment/c8s-system/c8s-operator"
	controlPlaneNodeLabel = "node-role.kubernetes.io/control-plane"
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
	}
}

// workerControlPlaneRenderConfig is the control-plane render of the worker
// image build's configuration, with the operator's webhooks at 127.0.0.1.
func workerControlPlaneRenderConfig() workerControlPlaneConfig {
	return workerControlPlaneConfig{
		nodeImageRenderConfig: workerRenderConfig(),
		webhookHost:           "127.0.0.1",
	}
}

// workerTestDocument is the workers' document a render needs.
func workerTestDocument() *worker.Document {
	return &worker.Document{Kubernetes: worker.Kubernetes{ClusterDNS: "10.53.0.10"}}
}

// renderTestWorkerCluster is worker control-plane render's cluster.yaml for
// the worker image build's configuration on platform.
func renderTestWorkerCluster(t *testing.T, platform string) map[string]unstructured.Unstructured {
	t.Helper()
	cfg := workerControlPlaneRenderConfig()
	cfg.platform = platform
	cluster, operator, err := renderWorkerCluster(context.Background(), cfg, workerTestDocument())
	if err != nil {
		t.Fatal(err)
	}
	if operator != nil {
		t.Fatalf("%s: the render wrote operator.yaml without --control-plane-nodes", platform)
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
			t.Fatalf("router nodeSelector = %v, want current CDS eligibility", pod.NodeSelector)
		}
	}
}

// --pod-cvm-provider adds the provider's grants, bound to the operator's user.
func TestWorkerClusterGrantsThePodCVMProvider(t *testing.T) {
	cfg := workerControlPlaneRenderConfig()
	cfg.podCVMProvider = true
	cluster, _, err := renderWorkerCluster(context.Background(), cfg, workerTestDocument())
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

// operatorDeployment is the operator Deployment of a render.
func operatorDeployment(t *testing.T, objects map[string]unstructured.Unstructured) appsv1.Deployment {
	t.Helper()
	var d appsv1.Deployment
	data, err := yaml.Marshal(objects[operatorDeploymentKey].Object)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &d); err != nil || len(d.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("no operator Deployment: %v", err)
	}
	return d
}

// --control-plane-nodes renders operator.yaml, the pod a control-plane node
// runs in place of the process an administrator starts by hand.
func TestWorkerOperatorPodRunsOnTheControlPlaneNodes(t *testing.T) {
	cfg := workerControlPlaneRenderConfig()
	cfg.controlPlaneNodes = true
	cluster, operator, err := renderWorkerCluster(context.Background(), cfg, workerTestDocument())
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(renderedObjects(t, cluster))); !slices.Equal(got, workerClusterObjects) {
		t.Fatalf("cluster.yaml objects = %v, want %v", got, workerClusterObjects)
	}
	objects := renderedObjects(t, operator)
	if got := slices.Sorted(maps.Keys(objects)); !slices.Equal(got, workerOperatorObjects) {
		t.Fatalf("operator.yaml objects = %v, want %v", got, workerOperatorObjects)
	}
	deployment := operatorDeployment(t, objects)
	if replicas := deployment.Spec.Replicas; replicas == nil || *replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Fatalf("the operator rolls as %v/%s, want one pod recreated", deployment.Spec.Replicas, deployment.Spec.Strategy.Type)
	}
	pod := deployment.Spec.Template.Spec
	if !pod.HostNetwork {
		t.Error("the operator's pod serves its webhook on its node's address, which takes the host network")
	}
	account := objects["ServiceAccount/c8s-system/c8s-operator"]
	if pod.ServiceAccountName != account.GetName() {
		t.Errorf("the pod authenticates as %q, want the rendered ServiceAccount", pod.ServiceAccountName)
	}
	if !maps.Equal(pod.NodeSelector, map[string]string{controlPlaneNodeLabel: ""}) {
		t.Errorf("nodeSelector = %v, want the control-plane nodes", pod.NodeSelector)
	}
	if !slices.ContainsFunc(pod.Tolerations, func(toleration corev1.Toleration) bool {
		return toleration.Key == controlPlaneNodeLabel && toleration.Operator == corev1.TolerationOpExists
	}) {
		t.Errorf("tolerations = %v, want the control-plane taint tolerated", pod.Tolerations)
	}
	container := pod.Containers[0]
	image := cfg.imageRepository + "@" + cfg.imageDigest
	if container.Image != image {
		t.Errorf("image = %q, want the release's %q", container.Image, image)
	}
	args := []string{
		"operator",
		"--webhook-host=" + cfg.webhookHost,
		"--get-cert-image=" + image,
		"--mesh-image=" + cfg.armtlsMeshImageRepository + "@" + cfg.armtlsMeshImageDigest,
	}
	if len(container.Command) == 0 || !slices.Equal(container.Args, args) {
		t.Errorf("%v %v, want the image's entrypoint and %v", container.Command, container.Args, args)
	}
}

// The pod is as unprivileged as the chart lane's operator, and writes its
// webhook serving certificate to a volume rather than the image.
func TestWorkerOperatorPodIsUnprivileged(t *testing.T) {
	cfg := workerControlPlaneRenderConfig()
	cfg.controlPlaneNodes = true
	_, operator, err := renderWorkerCluster(context.Background(), cfg, workerTestDocument())
	if err != nil {
		t.Fatal(err)
	}
	deployment := operatorDeployment(t, renderedObjects(t, operator))
	pod := deployment.Spec.Template.Spec
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Error("the operator's pod must run as a non-root user")
	}
	if pod.SecurityContext == nil || pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("seccompProfile = %v, want RuntimeDefault", pod.SecurityContext.SeccompProfile)
	}
	container := pod.Containers[0]
	security := container.SecurityContext
	if security == nil || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem ||
		security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation ||
		security.Capabilities == nil || !slices.Equal(security.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Errorf("container securityContext = %+v, want a read-only root, no privilege escalation and no capabilities", security)
	}
	if container.Resources.Requests.Cpu().IsZero() || container.Resources.Requests.Memory().IsZero() {
		t.Errorf("resource requests = %v, want cpu and memory", container.Resources.Requests)
	}
	certDir := webhook.DefaultCertDir
	mount := slices.IndexFunc(container.VolumeMounts, func(mount corev1.VolumeMount) bool {
		return strings.HasPrefix(certDir, mount.MountPath) && !mount.ReadOnly
	})
	if mount < 0 {
		t.Fatalf("volumeMounts = %v, want a writable volume holding %s", container.VolumeMounts, certDir)
	}
	name := container.VolumeMounts[mount].Name
	volume := slices.IndexFunc(pod.Volumes, func(volume corev1.Volume) bool {
		return volume.Name == name && volume.EmptyDir != nil
	})
	if volume < 0 {
		t.Errorf("volumes = %v, want %s as an emptyDir", pod.Volumes, name)
	}
}

// The pod's bindings give its ServiceAccount what the user c8s-operator holds.
func TestWorkerOperatorPodHoldsTheOperatorUsersGrants(t *testing.T) {
	cfg := workerControlPlaneRenderConfig()
	cfg.controlPlaneNodes = true
	cluster, operator, err := renderWorkerCluster(context.Background(), cfg, workerTestDocument())
	if err != nil {
		t.Fatal(err)
	}
	clusterObjects, operatorObjects := renderedObjects(t, cluster), renderedObjects(t, operator)
	userRole, _, _ := unstructured.NestedStringMap(clusterObjects["ClusterRoleBinding//c8s-operator"].Object, "roleRef")
	podRole, _, _ := unstructured.NestedStringMap(operatorObjects["ClusterRoleBinding//c8s-operator-pod"].Object, "roleRef")
	if len(podRole) == 0 || !maps.Equal(podRole, userRole) {
		t.Fatalf("the pod's binding names %v, want the user's %v", podRole, userRole)
	}
	account := map[string]any{"kind": "ServiceAccount", "name": "c8s-operator", "namespace": nodeImageNamespace}
	subjects, _, _ := unstructured.NestedSlice(operatorObjects["ClusterRoleBinding//c8s-operator-pod"].Object, "subjects")
	if len(subjects) != 1 || !maps.Equal(subjects[0].(map[string]any), account) {
		t.Fatalf("the pod's binding subjects = %v, want the account %v alone", subjects, account)
	}
}
