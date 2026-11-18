package podprovider

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// A guest that was never sent the Pod runs no containers, so a grace period
// has nothing to wait for.
func TestDeletionDoesNotWaitForAPodItsGuestNeverReceived(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		cloud.in = instanceFor(req)
		cloud.in.Status = "provisioning"
		return cloud.in, nil
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if rec := getRecord(t, r, pod); !rec.CreateAttempted || len(rec.Assignment) != 0 {
		t.Fatalf("fixture: want a created instance with no assignment, got attempted=%t assignment=%d bytes", rec.CreateAttempted, len(rec.Assignment))
	}
	deleteWithGraceLeft(t, r, pod, 30*time.Second)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 {
		t.Fatalf("%d destruction requests for an unassigned Pod inside its grace period, want 1", cloud.deleteCalls)
	}
}

// A verification deadline that passes inside the grace period fails the Pod
// then, and its instance still stays until the grace period ends.
func TestVerificationDeadlineInsideTheGracePeriodFailsThePodAndKeepsItsInstance(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	end := deleteWithGraceLeft(t, r, pod, 30*time.Second)
	rec, secret, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := end.Add(-10 * time.Second)
	rec.VerificationDeadline = &deadline
	if err := r.save(context.Background(), rec, secret); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)}

	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 20*time.Second {
		t.Fatalf("requeued after %s, want the 20s until the verification deadline", res.RequeueAfter)
	}
	if got := getPod(t, r, pod); got.Status.Phase != corev1.PodRunning {
		t.Fatalf("Pod is %s before its verification deadline, want Running", got.Status.Phase)
	}

	r.now = func() time.Time { return deadline }
	for range 2 {
		if res, err = r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if got := getPod(t, r, pod); got.Status.Phase != corev1.PodFailed || got.Status.Reason != verificationTimeoutReason {
		t.Fatalf("Pod is %s/%s at its verification deadline, want Failed/%s", got.Status.Phase, got.Status.Reason, verificationTimeoutReason)
	}
	if cloud.deleteCalls != 0 || res.RequeueAfter != 10*time.Second {
		t.Fatalf("%d destruction requests, requeue %s: want the instance kept for the 10s left of the grace period", cloud.deleteCalls, res.RequeueAfter)
	}

	r.now = func() time.Time { return end }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 {
		t.Fatalf("%d destruction requests once the grace period passed, want 1", cloud.deleteCalls)
	}
}

// The Pod's author chooses its grace period, so a long one must not keep the
// instance past the operator's maximum.
func TestDeletionGraceIsBoundedByTheConfiguredMaximum(t *testing.T) {
	deleted := time.Now()
	r := &Reconciler{cfg: &Config{MaxDeletionGraceSeconds: 300}, now: func() time.Time { return deleted }}
	rec := &record{Assignment: []byte("sent")}
	for _, tc := range []struct{ grace, want int64 }{{0, 0}, {120, 120}, {300, 300}, {86400, 300}} {
		pod := fixturePod()
		pod.DeletionTimestamp = &metav1.Time{Time: deleted.Add(time.Duration(tc.grace) * time.Second)}
		pod.DeletionGracePeriodSeconds = &tc.grace
		if got := r.graceRemaining(pod, rec); got != time.Duration(tc.want)*time.Second {
			t.Fatalf("grace period %ds: instance left for %s, want %ds", tc.grace, got, tc.want)
		}
	}
}

func TestMaxDeletionGraceBoundsAndDefault(t *testing.T) {
	for _, seconds := range []int64{-1, 0, 1, 300, 3600, 3601} {
		cfg := fixtureConfig(t)
		cfg.MaxDeletionGraceSeconds = seconds
		err := cfg.validate()
		if valid := seconds >= 0 && seconds <= 3600; (err == nil) != valid {
			t.Fatalf("maximum %d: %v", seconds, err)
		}
		if seconds == 0 && cfg.MaxDeletionGraceSeconds != 300 {
			t.Fatal("missing default")
		}
	}
}
