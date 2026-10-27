package controller

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// pod builds a test pod. ownerKind == "" means a bare (unowned) pod.
func pod(name, ns, ownerKind string, ann map[string]string) *corev1.Pod {
	p := &corev1.Pod{
		Name: name, Namespace: ns, Annotations: ann,
	}
	if ownerKind != "" {
		controller := true
		p.OwnerReferences = []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: ownerKind, Name: name + "-owner", UID: types.UID("uid-" + name), Controller: &controller},
		}
	}
	return p
}

func TestReinjectSweepDeletesOnlyOwnedUninjectedWorkloadPods(t *testing.T) {
	cw := map[string]string{webhook.AnnotationWorkload: "wl"}
	cwInjected := map[string]string{webhook.AnnotationWorkload: "wl", webhook.AnnotationInjected: "true"}

	pods := []client.Object{
		// Deleted: owned, cw, never injected, covered namespace.
		pod("needs", "tenant", "ReplicaSet", cw),
		pod("needs-sts", "tenant", "StatefulSet", cw),
		// Kept: already injected.
		pod("injected", "tenant", "ReplicaSet", cwInjected),
		// Kept: no cw annotation (not opted in).
		pod("no-cw", "tenant", "ReplicaSet", nil),
		// Guest-owned injection must not trigger deletion and recreation on operator restart.
		pod("pod-cvm", "tenant", "ReplicaSet", map[string]string{webhook.AnnotationWorkload: "wl", webhook.AnnotationPodCVM: "true"}),
		// Kept: bare pod (no controller would recreate it).
		pod("bare", "tenant", "", cw),
		// Kept: excluded namespace (webhook never injects there).
		pod("in-release", "c8s-system", "ReplicaSet", cw),
		pod("in-kube", "kube-system", "ReplicaSet", cw),
		pod("in-provisioner", "local-path-storage", "ReplicaSet", cw),
		pod("in-extra", "skip-me", "ReplicaSet", cw),
	}

	c := fake.NewClientBuilder().WithObjects(pods...).Build()
	excluded := excludedNamespaceSet("c8s-system", []string{"skip-me"})

	if err := reinjectSweep(context.Background(), c, excluded); err != nil {
		t.Fatalf("reinjectSweep: %v", err)
	}

	var remaining corev1.PodList
	if err := c.List(context.Background(), &remaining); err != nil {
		t.Fatalf("list: %v", err)
	}
	got := make([]string, 0, len(remaining.Items))
	for _, p := range remaining.Items {
		got = append(got, p.Name)
	}
	sort.Strings(got)

	want := []string{"bare", "in-extra", "in-kube", "in-provisioner", "in-release", "injected", "no-cw", "pod-cvm"}
	if !slices.Equal(got, want) {
		t.Fatalf("surviving pods = %v, want %v", got, want)
	}
}

func TestReinjectSweepListError(t *testing.T) {
	c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return apierrors.NewInternalError(errors.New("boom"))
		},
	}).Build()
	if err := reinjectSweep(context.Background(), c, nil); err == nil {
		t.Fatal("reinjectSweep = nil, want list error")
	}
}

func TestReinjectSweepIgnoresDeleteNotFound(t *testing.T) {
	// The pod vanished between List and Delete (e.g. its owner replaced it):
	// NotFound must be swallowed, not surfaced.
	cw := map[string]string{webhook.AnnotationWorkload: "wl"}
	c := fake.NewClientBuilder().
		WithObjects(pod("gone", "tenant", "ReplicaSet", cw)).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				return apierrors.NewNotFound(corev1.Resource("pods"), obj.GetName())
			},
		}).Build()
	if err := reinjectSweep(context.Background(), c, nil); err != nil {
		t.Fatalf("reinjectSweep: %v", err)
	}
}

func TestReinjectSweepDeleteErrorSurfaces(t *testing.T) {
	cw := map[string]string{webhook.AnnotationWorkload: "wl"}
	c := fake.NewClientBuilder().
		WithObjects(pod("stuck", "tenant", "ReplicaSet", cw)).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return apierrors.NewInternalError(errors.New("boom"))
			},
		}).Build()
	if err := reinjectSweep(context.Background(), c, nil); err == nil {
		t.Fatal("reinjectSweep = nil, want delete error")
	}
}

// The completion log is the sweep's audit record: its counters must reflect
// what actually happened.
func TestReinjectSweepReportsCounts(t *testing.T) {
	cw := map[string]string{webhook.AnnotationWorkload: "wl"}
	c := fake.NewClientBuilder().WithObjects(
		pod("owned-1", "tenant", "ReplicaSet", cw),
		pod("owned-2", "tenant", "StatefulSet", cw),
		pod("bare", "tenant", "", cw),
	).Build()

	rec := newLogRecorder()
	ctx := log.IntoContext(context.Background(), rec.logger())
	if err := reinjectSweep(ctx, c, nil); err != nil {
		t.Fatalf("reinjectSweep: %v", err)
	}

	e, ok := rec.find("reinject sweep complete")
	if !ok {
		t.Fatal("completion log entry missing")
	}
	if deleted, ok := e.kv["deleted"].(int); !ok || deleted != 2 {
		t.Fatalf("deleted = %v, want 2", e.kv["deleted"])
	}
	if skipped, ok := e.kv["skipped_bare"].(int); !ok || skipped != 1 {
		t.Fatalf("skipped_bare = %v, want 1", e.kv["skipped_bare"])
	}
}

func TestExcludedNamespaceSetManyExtras(t *testing.T) {
	got := excludedNamespaceSet("rel", []string{"a", "b", "c", "d", "e", " f ", ""})
	want := map[string]struct{}{
		"rel": {}, "kube-system": {}, "kube-public": {}, "kube-node-lease": {}, "local-path-storage": {},
		"a": {}, "b": {}, "c": {}, "d": {}, "e": {}, "f": {},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("excludedNamespaceSet = %v, want %v", got, want)
	}
}

func TestNeedsReinjectSkipsTerminatingPod(t *testing.T) {
	excluded := excludedNamespaceSet("c8s-system", nil)
	p := pod("term", "tenant", "ReplicaSet", map[string]string{webhook.AnnotationWorkload: "wl"})
	now := metav1.Now()
	p.DeletionTimestamp = &now
	if needsReinject(p, excluded) {
		t.Fatal("terminating pod should not be swept")
	}
}

func TestRunReinjectSweep(t *testing.T) {
	mgr := newTestManager(t)
	excluded := excludedNamespaceSet("c8s-system", nil)

	t.Run("client build failure is wrapped", func(t *testing.T) {
		stubDirectClient(t, nil, errors.New("boom"))
		err := runReinjectSweep(context.Background(), mgr, excluded)
		if err == nil || !strings.Contains(err.Error(), "build sweep client: boom") {
			t.Fatalf("runReinjectSweep error = %v, want wrapped client-build error", err)
		}
	})

	t.Run("sweeps through the built client", func(t *testing.T) {
		cw := map[string]string{webhook.AnnotationWorkload: "wl"}
		fc := fake.NewClientBuilder().WithObjects(pod("needs", "tenant", "ReplicaSet", cw)).Build()
		stubDirectClient(t, fc, nil)
		if err := runReinjectSweep(context.Background(), mgr, excluded); err != nil {
			t.Fatalf("runReinjectSweep: %v", err)
		}
		var p corev1.Pod
		err := fc.Get(context.Background(), client.ObjectKey{Namespace: "tenant", Name: "needs"}, &p)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("uninjected cw pod still present after sweep (get err = %v)", err)
		}
	})
}
