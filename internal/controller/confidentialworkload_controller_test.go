package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/confidential-dot-ai/confidential-kubernetes/api/v1alpha2"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/webhook"
)

// cwPod builds a pod carrying the cw workload annotation; ready toggles the
// PodReady=True condition that isPodReady keys on.
func cwPod(name, ns, cwName string, ready bool) *corev1.Pod {
	p := &corev1.Pod{
		Name:        name,
		Namespace:   ns,
		Annotations: map[string]string{webhook.AnnotationWorkload: cwName},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		}
	} else {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionFalse},
		}
	}
	return p
}

func confidentialWorkload(ns, name string, generation int64) *v1alpha2.ConfidentialWorkload {
	return &v1alpha2.ConfidentialWorkload{
		Name: name, Namespace: ns, Generation: generation,
		Spec: v1alpha2.ConfidentialWorkloadSpec{
			WorkloadRef: v1alpha2.WorkloadRef{Kind: v1alpha2.WorkloadKindDeployment, Name: name},
		},
	}
}

func cwReconcilerFor(objs ...client.Object) *ConfidentialWorkloadReconciler {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&v1alpha2.ConfidentialWorkload{}).
		Build()
	return &ConfidentialWorkloadReconciler{Client: c}
}

func cwReconcile(t *testing.T, r *ConfidentialWorkloadReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: ns, Name: name,
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return res
}

func getCW(t *testing.T, c client.Client, ns, name string) *v1alpha2.ConfidentialWorkload {
	t.Helper()
	var cw v1alpha2.ConfidentialWorkload
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &cw); err != nil {
		t.Fatalf("get ConfidentialWorkload %s/%s: %v", ns, name, err)
	}
	return &cw
}

func TestConfidentialWorkloadResolvesWorkloadRefCWID(t *testing.T) {
	const ns = "tenant"
	// The referenced workload's pods carry cw id "api-id", which differs from
	// the CW object's own name "cw-name". Matching on cw.Name (the pre-fix
	// behavior) would count the wrong pod; resolving spec.workloadRef finds the
	// real member pods (M-09).
	dep := &appsv1.Deployment{
		Name: "api-deploy", Namespace: ns,
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{webhook.AnnotationWorkload: "api-id"},
				},
			},
		},
	}
	cw := &v1alpha2.ConfidentialWorkload{
		Name: "cw-name", Namespace: ns, Generation: 1,
		Spec: v1alpha2.ConfidentialWorkloadSpec{
			WorkloadRef: v1alpha2.WorkloadRef{Kind: v1alpha2.WorkloadKindDeployment, Name: "api-deploy"},
		},
	}
	// Two member pods carry the workload's cw id; a decoy pod carries the CW
	// object name and must NOT be counted.
	p1 := cwPod("p1", ns, "api-id", true)
	p2 := cwPod("p2", ns, "api-id", false)
	decoy := cwPod("decoy", ns, "cw-name", true)

	r := cwReconcilerFor(cw, dep, p1, p2, decoy)
	cwReconcile(t, r, ns, "cw-name")

	sum := getCW(t, r.Client, ns, "cw-name").Status.AttestationSummary
	if sum == nil || sum.Total != 2 || sum.Attested != 1 {
		t.Fatalf("summary = %#v, want Total=2 Attested=1 (matched via workloadRef cw id, decoy excluded)", sum)
	}
}

func TestConfidentialWorkloadReconcileNotFoundIsNoOp(t *testing.T) {
	r := cwReconcilerFor()
	res := cwReconcile(t, r, "tenant", "missing")
	// IgnoreNotFound: no error, no requeue scheduled.
	if res.RequeueAfter != 0 {
		t.Fatalf("requeue = %v, want 0 for a missing CW", res.RequeueAfter)
	}
}

func TestConfidentialWorkloadReconcileNoPods(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 3)
	r := cwReconcilerFor(cw)

	res := cwReconcile(t, r, "tenant", "wl")
	if res.RequeueAfter != statusMirrorRequeue {
		t.Fatalf("requeue = %v, want %v", res.RequeueAfter, statusMirrorRequeue)
	}

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary == nil ||
		got.Status.AttestationSummary.Total != 0 || got.Status.AttestationSummary.Attested != 0 {
		t.Fatalf("summary = %#v, want 0/0", got.Status.AttestationSummary)
	}
	if got.Status.ObservedGeneration != 3 {
		t.Fatalf("observedGeneration = %d, want 3", got.Status.ObservedGeneration)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, v1alpha2.ConditionAttested)
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "NoPods" {
		t.Fatalf("condition = %#v, want Unknown/NoPods", cond)
	}
}

func TestConfidentialWorkloadReconcileAllAttested(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(
		cw,
		cwPod("p1", "tenant", "wl", true),
		cwPod("p2", "tenant", "wl", true),
		// Different workload in the same namespace: must not be counted.
		cwPod("other", "tenant", "elsewhere", true),
		// No cw annotation: ignored.
		&corev1.Pod{Name: "bare", Namespace: "tenant"},
	)

	cwReconcile(t, r, "tenant", "wl")

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary.Total != 2 || got.Status.AttestationSummary.Attested != 2 {
		t.Fatalf("summary = %#v, want 2/2", got.Status.AttestationSummary)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, v1alpha2.ConditionAttested)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "AllAttested" {
		t.Fatalf("condition = %#v, want True/AllAttested", cond)
	}
}

func TestConfidentialWorkloadReconcilePartialAttestation(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(
		cw,
		cwPod("ready", "tenant", "wl", true),
		cwPod("pending", "tenant", "wl", false),
	)

	cwReconcile(t, r, "tenant", "wl")

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary.Total != 2 || got.Status.AttestationSummary.Attested != 1 {
		t.Fatalf("summary = %#v, want 1/2", got.Status.AttestationSummary)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, v1alpha2.ConditionAttested)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "PendingAttestation" {
		t.Fatalf("condition = %#v, want False/PendingAttestation", cond)
	}
}

func TestConfidentialWorkloadReconcileIgnoresOtherNamespace(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(
		cw,
		// Same cw name but a different namespace: List is namespace-scoped, so
		// this pod must not be counted.
		cwPod("foreign", "other", "wl", true),
	)

	cwReconcile(t, r, "tenant", "wl")

	got := getCW(t, r.Client, "tenant", "wl")
	if got.Status.AttestationSummary.Total != 0 {
		t.Fatalf("total = %d, want 0 (pod is in another namespace)", got.Status.AttestationSummary.Total)
	}
}

func TestConfidentialWorkloadReconcileIsIdempotent(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	r := cwReconcilerFor(cw, cwPod("p1", "tenant", "wl", true))

	cwReconcile(t, r, "tenant", "wl")
	first := getCW(t, r.Client, "tenant", "wl")
	firstRV := first.ResourceVersion

	// A second reconcile with unchanged state must short-circuit on the
	// DeepEqual guard and not bump the resourceVersion via a status update.
	res := cwReconcile(t, r, "tenant", "wl")
	if res.RequeueAfter != statusMirrorRequeue {
		t.Fatalf("requeue = %v, want %v", res.RequeueAfter, statusMirrorRequeue)
	}
	second := getCW(t, r.Client, "tenant", "wl")
	if second.ResourceVersion != firstRV {
		t.Fatalf("resourceVersion changed on no-op reconcile: %q -> %q", firstRV, second.ResourceVersion)
	}
}

func TestResolveWorkloadCWIDFallsBackToCWName(t *testing.T) {
	const ns = "tenant"
	depNoAnnotation := &appsv1.Deployment{
		Name: "plain", Namespace: ns,
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{}},
	}
	cwWith := func(kind v1alpha2.WorkloadKind, refName string) *v1alpha2.ConfidentialWorkload {
		return &v1alpha2.ConfidentialWorkload{
			Name: "cw-name", Namespace: ns,
			Spec: v1alpha2.ConfidentialWorkloadSpec{
				WorkloadRef: v1alpha2.WorkloadRef{Kind: kind, Name: refName},
			},
		}
	}
	tests := []struct {
		name string
		cw   *v1alpha2.ConfidentialWorkload
	}{
		{"unsupported ref kind", cwWith(v1alpha2.WorkloadKind("CronJob"), "x")},
		{"empty ref name", cwWith(v1alpha2.WorkloadKindDeployment, "")},
		{"referenced workload missing", cwWith(v1alpha2.WorkloadKindDeployment, "gone")},
		{"workload without cw annotation", cwWith(v1alpha2.WorkloadKindDeployment, "plain")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := cwReconcilerFor(depNoAnnotation.DeepCopy())
			if got := r.resolveWorkloadCWID(context.Background(), tc.cw); got != "cw-name" {
				t.Fatalf("resolveWorkloadCWID = %q, want the CW name fallback", got)
			}
		})
	}
}

func TestConfidentialWorkloadListPodsErrorSurfaces(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cw).
		WithStatusSubresource(&v1alpha2.ConfidentialWorkload{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return apierrors.NewInternalError(errors.New("boom"))
			},
		}).Build()
	r := &ConfidentialWorkloadReconciler{Client: c}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "wl",
	})
	if err == nil || !strings.Contains(err.Error(), "list pods") {
		t.Fatalf("err = %v, want list pods failure", err)
	}
}

func TestConfidentialWorkloadStatusUpdateErrorSurfaces(t *testing.T) {
	cw := confidentialWorkload("tenant", "wl", 1)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cw).
		WithStatusSubresource(&v1alpha2.ConfidentialWorkload{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
				return apierrors.NewInternalError(errors.New("boom"))
			},
		}).Build()
	r := &ConfidentialWorkloadReconciler{Client: c}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		Namespace: "tenant", Name: "wl",
	})
	if err == nil || !strings.Contains(err.Error(), "status update") {
		t.Fatalf("err = %v, want status update failure", err)
	}
}

func TestIsPodReady(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"ready", cwPod("a", "ns", "wl", true), true},
		{"not ready", cwPod("b", "ns", "wl", false), false},
		{"no conditions", &corev1.Pod{}, false},
		{
			name: "other condition true only",
			pod: &corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
				{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
			}}},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPodReady(tc.pod); got != tc.want {
				t.Fatalf("isPodReady = %v, want %v", got, tc.want)
			}
		})
	}
}
