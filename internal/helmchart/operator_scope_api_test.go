package helmchart

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// KUBEBUILDER_ASSETS enables real API admission and RBAC with simulated client certificates.
func TestOperatorScopeAPI(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to run real API admission tests")
	}
	env := &envtest.Environment{}
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := func(name, group string) (*kubernetes.Clientset, *envtest.AuthenticatedUser) {
		t.Helper()
		u, err := env.AddUser(envtest.User{Name: name, Groups: []string{group}}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		c, err := kubernetes.NewForConfig(u.Config())
		if err != nil {
			t.Fatal(err)
		}
		return c, u
	}
	op, user := client("operator", "c8s:node-operators")
	logs, _ := client("log-reader", "c8s:log-readers")
	for _, f := range []string{"cred-release-rbac.yaml", "log-reader-rbac.yaml"} {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(operatorScopePolicyPath), f))
		if err != nil {
			t.Fatal(err)
		}
		var role rbacv1.ClusterRole
		var binding rbacv1.ClusterRoleBinding
		roleName, bindingName := "c8s-node-operator", "c8s-node-operators"
		if f == "log-reader-rbac.yaml" {
			roleName, bindingName = "c8s-log-reader", "c8s-log-readers"
		}
		if !findDoc(t, string(raw), "ClusterRole", roleName, &role) || !findDoc(t, string(raw), "ClusterRoleBinding", bindingName, &binding) {
			t.Fatal("missing baked RBAC")
		}
		if _, err := admin.RbacV1().ClusterRoles().Create(ctx, &role, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.RbacV1().ClusterRoleBindings().Create(ctx, &binding, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, ns := range []string{"c8s-router", "c8s-system", "tenant"} {
		if _, err := admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	vap, binding := loadImagePolicy(t, operatorScopePolicyPath, "confos-operator-scope")
	if _, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, &vap, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, &binding, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pod := func(name, selection string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"selection": selection}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: "fixture.invalid/image:v1"}}}}
	}
	var denyErr error
	if err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := op.CoreV1().Pods("kube-system").Create(ctx, pod("readiness", ""), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		denyErr = err
		return apierrors.IsInvalid(err) && strings.Contains(err.Error(), vap.Name), nil
	}); err != nil {
		t.Fatalf("policy did not enforce denial: %v (last response: %v)", err, denyErr)
	}
	create := func(ns, name, selection string) {
		t.Helper()
		if _, err := admin.CoreV1().Pods(ns).Create(ctx, pod(name, selection), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	zero := int64(0)
	del := metav1.DeleteOptions{GracePeriodSeconds: &zero}
	for _, name := range []string{"named", "selector", "collection-a", "collection-b", "unselected"} {
		selection := name
		if strings.HasPrefix(name, "collection-") {
			selection = "collection"
		}
		create("c8s-router", name, selection)
	}
	if err := logs.CoreV1().Pods("c8s-router").Delete(ctx, "unselected", del); !apierrors.IsForbidden(err) || strings.Contains(err.Error(), vap.Name) {
		t.Fatalf("log-reader delete must fail RBAC: %v", err)
	}
	if err := op.CoreV1().Pods("c8s-router").Delete(ctx, "named", del); err != nil {
		t.Fatal(err)
	}
	kubeconfig, err := user.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "operator.kubeconfig")
	if err := os.WriteFile(configPath, kubeconfig, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("KUBEBUILDER_ASSETS"), "kubectl"), "--kubeconfig", configPath, "-n", "c8s-router", "delete", "pods", "--selector=selection=selector", "--grace-period=0", "--wait=false")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("selector delete: %v: %s", err, out)
	}
	if err := op.CoreV1().Pods("c8s-router").DeleteCollection(ctx, del, metav1.ListOptions{LabelSelector: "selection=collection"}); err != nil {
		t.Fatal(err)
	}
	remaining, err := admin.CoreV1().Pods("c8s-router").List(ctx, metav1.ListOptions{})
	if err != nil || len(remaining.Items) != 1 || remaining.Items[0].Name != "unselected" {
		t.Fatalf("selected deletion changed wrong Pods: %v, %v", remaining, err)
	}
	for _, ns := range []string{"kube-system", "c8s-system"} {
		create(ns, "protected", "c8s-router")
		if err := op.CoreV1().Pods(ns).Delete(ctx, "protected", del); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), vap.Name) {
			t.Fatalf("protected namespace %s delete: %v", ns, err)
		}
	}
	if _, err := op.CoreV1().Pods("c8s-router").Create(ctx, pod("forbidden", ""), metav1.CreateOptions{}); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), vap.Name) {
		t.Fatalf("router create: %v", err)
	}
	if err := op.CoreV1().Namespaces().Delete(ctx, "c8s-router", del); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), vap.Name) {
		t.Fatalf("router namespace delete: %v", err)
	}
	if _, err := admin.CoreV1().Secrets("c8s-router").Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "protected"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := op.CoreV1().Secrets("c8s-router").Delete(ctx, "protected", del); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), vap.Name) {
		t.Fatalf("router Secret delete: %v", err)
	}
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "router"}, Spec: appsv1.DeploymentSpec{
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"selection": "router"}},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"selection": "router"}}, Spec: pod("", "").Spec},
	}}
	if _, err := admin.AppsV1().Deployments("c8s-router").Create(ctx, deployment, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := op.AppsV1().Deployments("c8s-router").Patch(ctx, "router", types.MergePatchType, []byte(`{"spec":{"replicas":0}}`), metav1.PatchOptions{}); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), vap.Name) {
		t.Fatalf("router Deployment patch: %v", err)
	}
	if err := op.AppsV1().Deployments("c8s-router").Delete(ctx, "router", del); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), vap.Name) {
		t.Fatalf("router Deployment delete: %v", err)
	}
	create("tenant", "ordinary", "")
	if err := op.CoreV1().Pods("tenant").Delete(ctx, "ordinary", del); err != nil {
		t.Fatalf("tenant delete: %v", err)
	}
}
