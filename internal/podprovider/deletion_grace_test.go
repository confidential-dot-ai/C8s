package podprovider

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// deleteWithGraceLeft deletes the Pod and sets the provider's clock so that
// left of its grace period remains. The fake client stamps the deletion with
// the current time whatever grace the delete asked for.
func deleteWithGraceLeft(t *testing.T, r *Reconciler, pod *corev1.Pod, left time.Duration) time.Time {
	t.Helper()
	if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	end := getPod(t, r, pod).DeletionTimestamp.Time
	r.now = func() time.Time { return end.Add(-left) }
	return end
}

func TestDeletionLeavesTheInstanceUntilTheGracePeriodHasPassed(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	end := deleteWithGraceLeft(t, r, pod, 30*time.Second)

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 0 {
		t.Fatal("instance destruction requested inside the grace period")
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("requeued after %s, want the 30s left of the grace period", res.RequeueAfter)
	}
	if !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) {
		t.Fatal("Pod released while its instance runs")
	}

	r.now = func() time.Time { return end }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 {
		t.Fatalf("%d destruction requests once the grace period passed, want 1", cloud.deleteCalls)
	}
}

// A grace period lets running containers stop. A Pod that already ended has
// none, so its deletion is not held.
func TestDeletionDoesNotWaitForAPodThatHasEnded(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	cloud.in.Status = "failed"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	deleteWithGraceLeft(t, r, pod, 30*time.Second)
	cloud.in.Status = "terminated"
	for range 2 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(pod), pod); !notFound(err) {
		t.Fatalf("ended Pod still held inside the grace period: %v", err)
	}
}
