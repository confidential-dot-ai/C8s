package nriimagepolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestWorkerRouterPlacementAPI(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	required := os.Getenv("C8S_REQUIRE_ENVTEST") == "1"
	if assets == "" && !required {
		t.Skip("set KUBEBUILDER_ASSETS to run Kubernetes authorization and admission checks")
	}
	env := &envtest.Environment{
		DownloadBinaryAssets:        required && assets == "",
		DownloadBinaryAssetsVersion: "1.36.0",
	}
	env.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "Node,RBAC").Append("enable-admission-plugins", "NodeRestriction")
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	admin, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	initial := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-a", Labels: map[string]string{"keep": "value", routerEligibleLabel: "true"}},
		Spec:       corev1.NodeSpec{Unschedulable: true, Taints: []corev1.Taint{{Key: "keep", Effect: corev1.TaintEffectNoSchedule}}},
	}
	own, err := admin.CoreV1().Nodes().Create(ctx, initial, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	expectedSpec := own.DeepCopy().Spec
	other, err := admin.CoreV1().Nodes().Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-b"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	user, err := env.AddUser(envtest.User{Name: "system:node:worker-a", Groups: []string{"system:nodes"}}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(user.Config())
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig, err := user.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, kubeconfig, 0o600); err != nil {
		t.Fatal(err)
	}
	worker := &config{Worker: true}
	workerAPI, err := worker.workerNodeClient(path, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.workerNodeClient(path, "worker-b"); err == nil {
		t.Fatal("credential for another worker accepted")
	}
	for _, eligible := range []bool{false, true} {
		own, err = publishRouterEligibility(ctx, workerAPI, own, eligible)
		if err != nil {
			t.Fatal(err)
		}
		if (own.Labels[routerEligibleLabel] == "true") != eligible || own.Labels["keep"] != "value" || !reflect.DeepEqual(own.Spec, expectedSpec) {
			t.Fatalf("eligibility update changed unrelated state: %+v", own)
		}
	}
	if _, err := publishRouterEligibility(ctx, client.CoreV1(), other, true); !apierrors.IsForbidden(err) {
		t.Fatalf("other Node update: %v, want forbidden", err)
	}
	protected := own.DeepCopy()
	protected.Labels["node-restriction.kubernetes.io/eligible"] = "true"
	if _, err := client.CoreV1().Nodes().Update(ctx, protected, metav1.UpdateOptions{}); !apierrors.IsForbidden(err) {
		t.Fatalf("protected label update: %v, want forbidden", err)
	}
	if _, err := admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "c8s-router"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pods, nodePods := admin.CoreV1().Pods("c8s-router"), client.CoreV1().Pods("c8s-router")
	create := func(name, worker string) *corev1.Pod {
		t.Helper()
		pod, err := pods.Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       corev1.PodSpec{NodeName: worker, Containers: []corev1.Container{{Name: "router", Image: "fixture.invalid/router:v1"}}},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return pod
	}
	pod := create("router-a", "worker-a")
	create("router-b", "worker-b")
	listed, err := nodePods.List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=worker-a"})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].UID != pod.UID {
		t.Fatalf("own-node pod list: %+v, %v", listed, err)
	}
	if _, err := nodePods.Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	options := metav1.DeleteOptions{GracePeriodSeconds: &zero, Preconditions: &metav1.Preconditions{UID: &pod.UID, ResourceVersion: &pod.ResourceVersion}}
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	ready, err := pods.UpdateStatus(ctx, pod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodePods.Delete(ctx, pod.Name, options); !apierrors.IsConflict(err) {
		t.Fatalf("delete after concurrent Ready update: %v, want conflict", err)
	}
	options.Preconditions.ResourceVersion = &ready.ResourceVersion
	if err := nodePods.Delete(ctx, pod.Name, options); err != nil {
		t.Fatal(err)
	}
	replacement := create(pod.Name, "worker-a")
	options.Preconditions.ResourceVersion = &replacement.ResourceVersion
	if err := nodePods.Delete(ctx, pod.Name, options); !apierrors.IsConflict(err) {
		t.Fatalf("delete replacement with old UID: %v, want conflict", err)
	}
}
