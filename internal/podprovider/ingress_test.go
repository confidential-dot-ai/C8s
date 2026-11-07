package podprovider

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ingressFixture(t *testing.T, objs ...client.Object) (*ingressReconciler, client.Client, *corev1.Pod) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-alice", Namespace: "agents", UID: "uid-1", Annotations: map[string]string{
			endpointsAnnotation: `[{"name":"app-4096","host":"203.0.113.5","port":30001},{"name":"app-8080","host":"203.0.113.5","port":30002}]`,
		}},
		Spec:   corev1.PodSpec{NodeName: "pod-cvm-node"},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(append([]client.Object{pod}, objs...)...).Build()
	return &ingressReconciler{client: c, nodeName: "pod-cvm-node", providerID: "test-provider"}, c, pod
}

func reconcileIngress(t *testing.T, r *ingressReconciler, pod *corev1.Pod) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	return err
}

func ingressObjects(t *testing.T, c client.Client) (*corev1.Service, *discoveryv1.EndpointSlice) {
	t.Helper()
	key := client.ObjectKey{Namespace: "agents", Name: "agent-alice"}
	svc, slice := &corev1.Service{}, &discoveryv1.EndpointSlice{}
	if err := c.Get(context.Background(), key, svc); err != nil {
		svc = nil
	}
	if err := c.Get(context.Background(), key, slice); err != nil {
		slice = nil
	}
	return svc, slice
}

func TestIngressPublishesPodEndpointsAsService(t *testing.T) {
	r, c, pod := ingressFixture(t)
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
	svc, slice := ingressObjects(t, c)
	if svc == nil || slice == nil {
		t.Fatal("Service or EndpointSlice missing")
	}
	if svc.Spec.Selector != nil || svc.Spec.Type != corev1.ServiceTypeClusterIP || len(svc.Spec.Ports) != 2 || svc.Spec.Ports[0].Port != 4096 || svc.Spec.Ports[1].Name != "app-8080" {
		t.Fatalf("service spec=%+v", svc.Spec)
	}
	for _, obj := range []metav1.Object{svc, slice} {
		if !metav1.IsControlledBy(obj, pod) {
			t.Fatalf("%s not owned by the pod: %+v", obj.GetName(), obj.GetOwnerReferences())
		}
	}
	if slice.Labels[discoveryv1.LabelServiceName] != pod.Name || slice.Labels[discoveryv1.LabelManagedBy] != ingressManager {
		t.Fatalf("slice labels=%v", slice.Labels)
	}
	if len(slice.Endpoints) != 1 || slice.Endpoints[0].Addresses[0] != "203.0.113.5" || !*slice.Endpoints[0].Conditions.Ready {
		t.Fatalf("slice endpoints=%+v", slice.Endpoints)
	}
	if len(slice.Ports) != 2 || *slice.Ports[0].Name != "app-4096" || *slice.Ports[0].Port != 30001 || *slice.Ports[1].Port != 30002 {
		t.Fatalf("slice ports=%+v", slice.Ports)
	}
}

func TestIngressFollowsEndpointAndReadinessChanges(t *testing.T) {
	r, c, pod := ingressFixture(t)
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
	pod.Annotations[endpointsAnnotation] = `[{"name":"app-4096","host":"203.0.113.9","port":31000}]`
	if err := c.Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	if err := c.Status().Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
	svc, slice := ingressObjects(t, c)
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 4096 {
		t.Fatalf("service ports=%+v", svc.Spec.Ports)
	}
	if slice.Endpoints[0].Addresses[0] != "203.0.113.9" || *slice.Ports[0].Port != 31000 || *slice.Endpoints[0].Conditions.Ready {
		t.Fatalf("slice=%+v", slice)
	}
}

func TestIngressWithdrawsWhenEndpointsGo(t *testing.T) {
	r, c, pod := ingressFixture(t)
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
	delete(pod.Annotations, endpointsAnnotation)
	if err := c.Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if svc, slice := ingressObjects(t, c); svc != nil || slice != nil {
		t.Fatal("withdrawn endpoints left a Service or EndpointSlice")
	}
	// A deleted Pod leaves nothing to reconcile; owner references collect the rest.
	if err := c.Delete(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
}

func TestIngressNeverAdoptsForeignService(t *testing.T) {
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "agent-alice", Namespace: "agents"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "web", Port: 80}}}}
	r, c, pod := ingressFixture(t, foreign)
	if err := reconcileIngress(t, r, pod); err == nil {
		t.Fatal("adopted a Service the pod does not own")
	}
	svc, slice := ingressObjects(t, c)
	if svc.Spec.Ports[0].Name != "web" || slice != nil {
		t.Fatalf("foreign Service changed or slice created: %+v %+v", svc.Spec.Ports, slice)
	}
	delete(pod.Annotations, endpointsAnnotation)
	if err := c.Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(foreign), &corev1.Service{}); err != nil {
		t.Fatalf("withdrawal deleted a foreign Service: %v", err)
	}
}

func TestIngressIgnoresOtherNodesAndRefusesBadEndpoints(t *testing.T) {
	r, c, pod := ingressFixture(t)
	r.nodeName = "other-node"
	if err := reconcileIngress(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if svc, _ := ingressObjects(t, c); svc != nil {
		t.Fatal("published a pod of another node")
	}
	r.nodeName = "pod-cvm-node"
	for _, bad := range []string{
		`[{"name":"pod-status","host":"203.0.113.5","port":30000}]`,
		`[{"name":"app-80","host":"203.0.113.5","port":30001},{"name":"app-81","host":"203.0.113.6","port":30002}]`,
		`not json`,
	} {
		pod.Annotations[endpointsAnnotation] = bad
		if err := c.Update(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
		_ = reconcileIngress(t, r, pod)
		if svc, slice := ingressObjects(t, c); svc != nil || slice != nil {
			t.Fatalf("published %s", bad)
		}
	}
}
