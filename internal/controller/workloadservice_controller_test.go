package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/confidential-dot-ai/confidential-kubernetes/api/v1alpha2"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/webhook"
)

func cwTemplate(cwID string, ports ...corev1.ContainerPort) corev1.PodTemplateSpec {
	var annotations map[string]string
	if cwID != "" {
		annotations = map[string]string{webhook.AnnotationWorkload: cwID}
	}
	return corev1.PodTemplateSpec{
		Labels:      map[string]string{"app": "x"},
		Annotations: annotations,
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "img", Ports: ports}},
		},
	}
}

func cwDeployment(ns, name, cwID string, ports ...corev1.ContainerPort) *appsv1.Deployment {
	return &appsv1.Deployment{
		Name: name, Namespace: ns, UID: types.UID("uid-" + name),
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: cwTemplate(cwID, ports...),
		},
	}
}

func reconcilerFor(kind v1alpha2.WorkloadKind, excluded map[string]struct{}, objs ...client.Object) *WorkloadServiceReconciler {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &WorkloadServiceReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: events.NewFakeRecorder(8),
		Kind:     kind,
		Excluded: excluded,
	}
}

func reconcile(t *testing.T, r *WorkloadServiceReconciler, ns, name string) {
	t.Helper()
	req := ctrl.Request{Namespace: ns, Name: name}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func getService(t *testing.T, c client.Client, ns, name string) *corev1.Service {
	t.Helper()
	var svc corev1.Service
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &svc); err != nil {
		t.Fatalf("get Service %s/%s: %v", ns, name, err)
	}
	return &svc
}

func TestWorkloadServiceCreatesHeadlessService(t *testing.T) {
	dep := cwDeployment("tenant", "vllm-router", "vllm-router",
		corev1.ContainerPort{Name: "http", ContainerPort: 8000},
	)
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep)
	reconcile(t, r, "tenant", "vllm-router")

	svc := getService(t, r.Client, "tenant", "c8s-vllm-router")
	if svc.Spec.ClusterIP != corev1.ClusterIPNone {
		t.Fatalf("clusterIP = %q, want None", svc.Spec.ClusterIP)
	}
	if got := svc.Spec.Selector[webhook.LabelWorkload]; got != "vllm-router" {
		t.Fatalf("selector = %v, want %s=vllm-router", svc.Spec.Selector, webhook.LabelWorkload)
	}
	if svc.Labels[managedByLabel] != managedByValue {
		t.Fatalf("labels = %v", svc.Labels)
	}
	owner := metav1.GetControllerOf(svc)
	if owner == nil || owner.Kind != "Deployment" || owner.Name != "vllm-router" {
		t.Fatalf("controller owner = %#v, want the Deployment", owner)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 8000 ||
		svc.Spec.Ports[0].Name != "port-8000" || svc.Spec.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Fatalf("ports = %#v", svc.Spec.Ports)
	}

	// Idempotent on re-reconcile.
	reconcile(t, r, "tenant", "vllm-router")
	getService(t, r.Client, "tenant", "c8s-vllm-router")
}

func TestWorkloadServiceSupportsStatefulSetAndDaemonSet(t *testing.T) {
	sts := &appsv1.StatefulSet{
		Name: "db", Namespace: "tenant", UID: "uid-db",
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: cwTemplate("db"),
		},
	}
	ds := &appsv1.DaemonSet{
		Name: "agent", Namespace: "tenant", UID: "uid-agent",
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: cwTemplate("agent"),
		},
	}

	r := reconcilerFor(v1alpha2.WorkloadKindStatefulSet, nil, sts, ds)
	reconcile(t, r, "tenant", "db")
	svc := getService(t, r.Client, "tenant", "c8s-db")
	if owner := metav1.GetControllerOf(svc); owner == nil || owner.Kind != "StatefulSet" {
		t.Fatalf("controller owner = %#v, want the StatefulSet", metav1.GetControllerOf(svc))
	}

	r.Kind = v1alpha2.WorkloadKindDaemonSet
	reconcile(t, r, "tenant", "agent")
	svc = getService(t, r.Client, "tenant", "c8s-agent")
	if owner := metav1.GetControllerOf(svc); owner == nil || owner.Kind != "DaemonSet" {
		t.Fatalf("controller owner = %#v, want the DaemonSet", metav1.GetControllerOf(svc))
	}
}

func TestWorkloadServiceAnnotationRemovalDeletesService(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep)
	reconcile(t, r, "tenant", "api")
	getService(t, r.Client, "tenant", "c8s-api")

	var live appsv1.Deployment
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "api"}, &live); err != nil {
		t.Fatal(err)
	}
	live.Spec.Template.Annotations = nil
	if err := r.Update(context.Background(), &live); err != nil {
		t.Fatal(err)
	}
	reconcile(t, r, "tenant", "api")

	err := r.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "c8s-api"}, &corev1.Service{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Service still present after annotation removal: err=%v", err)
	}
}

func TestWorkloadServiceCwRenameReplacesService(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep)
	reconcile(t, r, "tenant", "api")
	getService(t, r.Client, "tenant", "c8s-api")

	var live appsv1.Deployment
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "api"}, &live); err != nil {
		t.Fatal(err)
	}
	live.Spec.Template.Annotations[webhook.AnnotationWorkload] = "api-v2"
	if err := r.Update(context.Background(), &live); err != nil {
		t.Fatal(err)
	}
	reconcile(t, r, "tenant", "api")

	getService(t, r.Client, "tenant", "c8s-api-v2")
	err := r.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "c8s-api"}, &corev1.Service{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("old Service still present after cw rename: err=%v", err)
	}
}

func TestWorkloadServiceSkipsInvalidCwID(t *testing.T) {
	// Valid label value but not a DNS-1035 label part (dots), so no Service
	// name can be derived. Reconcile must not error or create anything.
	dep := cwDeployment("tenant", "api", "api.v1")
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep)
	reconcile(t, r, "tenant", "api")

	var svcs corev1.ServiceList
	if err := r.List(context.Background(), &svcs, client.InNamespace("tenant")); err != nil {
		t.Fatal(err)
	}
	if len(svcs.Items) != 0 {
		t.Fatalf("services = %d, want none for invalid cw id", len(svcs.Items))
	}
}

func TestWorkloadServiceDoesNotAdoptForeignService(t *testing.T) {
	foreign := &corev1.Service{
		Name: "c8s-api", Namespace: "tenant", UID: "uid-foreign",
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "user-owned"},
			Ports:    []corev1.ServicePort{{Name: "web", Port: 80}},
		},
	}
	dep := cwDeployment("tenant", "api", "api")
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep, foreign)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "api",
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// The foreign Service emits no watch events this controller sees, so the
	// collision must requeue to converge once the Service goes away.
	if res.RequeueAfter == 0 {
		t.Fatalf("expected a requeue while the name is occupied, got %#v", res)
	}
	select {
	case e := <-r.Recorder.(*events.FakeRecorder).Events:
		if !strings.Contains(e, "ServiceNameConflict") {
			t.Fatalf("event = %q, want ServiceNameConflict", e)
		}
	default:
		t.Fatal("expected a ServiceNameConflict event on the workload")
	}

	svc := getService(t, r.Client, "tenant", "c8s-api")
	if svc.Spec.Selector["app"] != "user-owned" || len(svc.OwnerReferences) != 0 {
		t.Fatalf("foreign Service was modified: %#v", svc)
	}
}

func TestWorkloadServiceSkipsExcludedNamespace(t *testing.T) {
	dep := cwDeployment("c8s-system", "api", "api")
	excluded := excludedNamespaceSet("c8s-system", nil)
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, excluded, dep)
	reconcile(t, r, "c8s-system", "api")

	var svcs corev1.ServiceList
	if err := r.List(context.Background(), &svcs, client.InNamespace("c8s-system")); err != nil {
		t.Fatal(err)
	}
	if len(svcs.Items) != 0 {
		t.Fatalf("services = %d, want none in excluded namespace", len(svcs.Items))
	}
}

func TestWorkloadServiceCleansUpWhenNamespaceBecomesExcluded(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")

	// Provision the Service while the namespace is covered.
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep)
	reconcile(t, r, "tenant", "api")
	getService(t, r.Client, "tenant", "c8s-api")

	// The namespace joins the exclusion list (operator restart with new
	// flags); the next reconcile must delete the now-stranded Service.
	r.Excluded = excludedNamespaceSet("c8s-system", []string{"tenant"})
	reconcile(t, r, "tenant", "api")

	err := r.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: "c8s-api"}, &corev1.Service{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Service still present after namespace became excluded: err=%v", err)
	}
}

func TestSetupWithManagerRejectsUnsupportedKind(t *testing.T) {
	r := &WorkloadServiceReconciler{Kind: v1alpha2.WorkloadKind("CronJob")}
	// nil manager is fine: the unsupported-kind guard returns before the
	// manager is ever touched.
	if err := r.SetupWithManager(nil); err == nil {
		t.Fatal("SetupWithManager(unsupported kind) = nil, want error")
	}
}

// reconcilerWithClient wraps a prebuilt client in a Deployment reconciler.
func reconcilerWithClient(c client.Client) *WorkloadServiceReconciler {
	return &WorkloadServiceReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: events.NewFakeRecorder(8),
		Kind:     v1alpha2.WorkloadKindDeployment,
	}
}

// staleManagedService builds a managed Service controlled by the given
// Deployment under a name the reconciler no longer desires.
func staleManagedService(name string, dep *appsv1.Deployment) *corev1.Service {
	controller := true
	return &corev1.Service{
		Name:      name,
		Namespace: dep.Namespace,
		Labels:    map[string]string{managedByLabel: managedByValue},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment",
			Name: dep.Name, UID: dep.UID, Controller: &controller,
		}}}
}

func TestWorkloadServiceMissingWorkloadIsNoOp(t *testing.T) {
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil)
	// Must not error: the Service is GC'd via ownerReference.
	reconcile(t, r, "tenant", "gone")
}

func TestWorkloadServiceGetErrorSurfaces(t *testing.T) {
	injected := apierrors.NewInternalError(errors.New("boom"))
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return injected
		},
	}).Build()
	r := reconcilerWithClient(c)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "api",
	})
	// The reconciler returns the Get failure unwrapped (only NotFound is
	// swallowed), so the exact injected error must surface.
	if !errors.Is(err, injected) {
		t.Fatalf("Reconcile err = %v, want the injected internal error", err)
	}
	if !apierrors.IsInternalError(err) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Reconcile err = %v, want an internal-error wrap of \"boom\"", err)
	}
}

func TestWorkloadServiceListErrorSurfaces(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return apierrors.NewInternalError(errors.New("boom"))
			},
		}).Build()
	r := reconcilerWithClient(c)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "api",
	})
	if err == nil || !strings.Contains(err.Error(), "list managed Services") {
		t.Fatalf("err = %v, want list managed Services failure", err)
	}
}

func TestWorkloadServiceDeleteStaleErrorSurfaces(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")
	stale := staleManagedService("c8s-old", dep)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, stale).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return apierrors.NewInternalError(errors.New("boom"))
			},
		}).Build()
	r := reconcilerWithClient(c)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "api",
	})
	if err == nil || !strings.Contains(err.Error(), "delete stale Service") {
		t.Fatalf("err = %v, want delete stale Service failure", err)
	}
}

func TestWorkloadServiceDeleteStaleIgnoresNotFound(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")
	stale := staleManagedService("c8s-old", dep)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, stale).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if obj.GetName() == "c8s-old" {
					return apierrors.NewNotFound(corev1.Resource("services"), obj.GetName())
				}
				return nil
			},
		}).Build()
	r := reconcilerWithClient(c)
	reconcile(t, r, "tenant", "api")
	// The desired Service must still be provisioned.
	getService(t, c, "tenant", "c8s-api")
}

func TestWorkloadServiceCreateErrorSurfaces(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return apierrors.NewInternalError(errors.New("boom"))
			},
		}).Build()
	r := reconcilerWithClient(c)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "api",
	})
	if err == nil || !strings.Contains(err.Error(), "ensure headless Service") {
		t.Fatalf("err = %v, want ensure headless Service failure", err)
	}
}

func TestWorkloadServiceAlreadyExistsRequeues(t *testing.T) {
	// The label-scoped cache view of a collision: no Service visible, but
	// Create races with a foreign object and gets AlreadyExists.
	dep := cwDeployment("tenant", "api", "api")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				return apierrors.NewAlreadyExists(corev1.Resource("services"), obj.GetName())
			},
		}).Build()
	r := reconcilerWithClient(c)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "api",
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != collisionRequeue {
		t.Fatalf("requeue = %v, want %v", res.RequeueAfter, collisionRequeue)
	}
}

// The unnameable-id log is the only operator-visible signal that a workload
// opted in but cannot get a headless Service; it must fire exactly for a
// non-empty id that yields no Service name.
func TestWorkloadServiceLogsUnnameableCwID(t *testing.T) {
	tests := []struct {
		name     string
		cwID     string
		wantSkip bool
	}{
		{"unnameable id is reported", "api.v1", true},
		{"empty id is silent", "", false},
		{"nameable id is silent", "api", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dep := cwDeployment("tenant", "api", tc.cwID)
			r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep)
			rec := newLogRecorder()
			ctx := log.IntoContext(context.Background(), rec.logger())
			if _, err := r.Reconcile(ctx, ctrl.Request{
				Namespace: "tenant", Name: "api",
			}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			_, got := rec.find("cw id does not yield a valid Service name; skipping headless Service")
			if got != tc.wantSkip {
				t.Fatalf("skip log present = %v, want %v", got, tc.wantSkip)
			}
		})
	}
}

// The reconcile log fires only when the Service actually changed.
func TestWorkloadServiceLogsReconcileOnlyOnChange(t *testing.T) {
	dep := cwDeployment("tenant", "api", "api")
	r := reconcilerFor(v1alpha2.WorkloadKindDeployment, nil, dep)

	first := newLogRecorder()
	ctx := log.IntoContext(context.Background(), first.logger())
	if _, err := r.Reconcile(ctx, ctrl.Request{
		Namespace: "tenant", Name: "api",
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := first.find("headless Service reconciled"); !ok {
		t.Fatal("expected a reconcile log entry on create")
	}

	second := newLogRecorder()
	ctx = log.IntoContext(context.Background(), second.logger())
	if _, err := r.Reconcile(ctx, ctrl.Request{
		Namespace: "tenant", Name: "api",
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := second.find("headless Service reconciled"); ok {
		t.Fatal("no-op reconcile must not log a Service change")
	}
}

func TestServicePortsMirrorsAndDedupes(t *testing.T) {
	template := corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "sidecar",
				Ports: []corev1.ContainerPort{{ContainerPort: 9090}},
			}},
			Containers: []corev1.Container{
				{
					Name: "app",
					Ports: []corev1.ContainerPort{
						{Name: "http", ContainerPort: 8000},
						{ContainerPort: 8000}, // duplicate port/protocol dropped
						{ContainerPort: 9000, Protocol: corev1.ProtocolUDP},
					},
				},
				{
					Name:  "metrics",
					Ports: []corev1.ContainerPort{{ContainerPort: 2112}},
				},
			},
		},
	}

	want := []corev1.ServicePort{
		{Name: "port-9090", Port: 9090, Protocol: corev1.ProtocolTCP},
		{Name: "port-8000", Port: 8000, Protocol: corev1.ProtocolTCP},
		{Name: "port-9000-udp", Port: 9000, Protocol: corev1.ProtocolUDP},
		{Name: "port-2112", Port: 2112, Protocol: corev1.ProtocolTCP},
	}
	if got := servicePorts(&template); !slices.Equal(got, want) {
		t.Fatalf("ports = %#v, want %#v", got, want)
	}
}
