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

// The assignment is saved before it is sent. A Pod deleted between the two
// reached no guest, so its grace period has nothing to wait for either.
func TestDeletionDoesNotWaitForAnAssignmentThatWasNeverSent(t *testing.T) {
	pod := fixturePod()
	r, cloud, guest := fixture(t, pod)
	guest.afterPrepare = func() {
		if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
			t.Fatal(err)
		}
	}
	for range 8 {
		if guest.prepares != 0 {
			break
		}
		_ = reconcile(t, r, pod)
	}
	if rec := getRecord(t, r, pod); len(rec.Assignment) == 0 || guest.sends != 0 {
		t.Fatalf("fixture: want a saved assignment that was never sent, got %d bytes and %d sends", len(rec.Assignment), guest.sends)
	}
	end := getPod(t, r, pod).DeletionTimestamp.Time
	r.now = func() time.Time { return end.Add(-30 * time.Second) }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if guest.sends != 0 || cloud.deleteCalls != 1 {
		t.Fatalf("%d sends, %d destruction requests for a Pod whose assignment was never sent, want 0 and 1", guest.sends, cloud.deleteCalls)
	}
}

// A send whose answer was lost may have reached the guest, so the Pod is
// held like one the guest acknowledged.
func TestDeletionWaitsForAnAssignmentWhoseSendWasNotAnswered(t *testing.T) {
	pod := fixturePod()
	r, cloud, guest := fixture(t, pod)
	guest.lostResponse = true
	for range 8 {
		if guest.sends != 0 {
			break
		}
		_ = reconcile(t, r, pod)
	}
	if guest.sends != 1 {
		t.Fatalf("fixture: %d sends, want 1", guest.sends)
	}
	deleteWithGraceLeft(t, r, pod, 30*time.Second)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 0 {
		t.Fatal("instance destruction requested inside the grace period of a Pod its guest may hold")
	}
}

// A provider that was away while both passed still reports the one that
// ended the wait: the earlier of the verification deadline and the end of the
// grace period, bounded by the maximum.
func TestDeletionResumedLateReportsWhatEndedTheWait(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grace    int64
		deadline time.Duration // after the deletion
		timedOut bool
	}{
		{"deadline first", 120, 60 * time.Second, true},
		{"grace period first", 120, 180 * time.Second, false},
		{"maximum first", 86400, 600 * time.Second, false},
		{"deadline before the maximum", 86400, 200 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := fixturePod()
			pod.Finalizers = []string{"example.invalid/hold"}
			r, cloud := fixtureReconciler(t, pod)
			runToRunning(t, r, pod)
			if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
				t.Fatal(err)
			}
			// The fake client stamps the deletion with the current time, so the
			// requested grace period is carried by the field alone and the
			// deletion is taken to have happened that long before the stamp.
			live := getPod(t, r, pod)
			live.DeletionGracePeriodSeconds = &tc.grace
			if err := r.client.Update(context.Background(), live); err != nil {
				t.Fatal(err)
			}
			deleted := live.DeletionTimestamp.Add(-time.Duration(tc.grace) * time.Second)
			rec, secret, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID)))
			if err != nil {
				t.Fatal(err)
			}
			deadline := deleted.Add(tc.deadline)
			rec.VerificationDeadline = &deadline
			if err := r.save(context.Background(), rec, secret); err != nil {
				t.Fatal(err)
			}
			r.now = func() time.Time { return deleted.Add(48 * time.Hour) }
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			if cloud.deleteCalls != 1 {
				t.Fatalf("%d destruction requests, want 1", cloud.deleteCalls)
			}
			got := getPod(t, r, pod)
			if timedOut := got.Status.Phase == corev1.PodFailed && got.Status.Reason == verificationTimeoutReason; timedOut != tc.timedOut {
				t.Fatalf("Pod is %s/%q, want verification timeout reported: %t", got.Status.Phase, got.Status.Reason, tc.timedOut)
			}
		})
	}
}

// Deleting a Pod must not keep an unverified guest longer than leaving it
// would: a verification deadline inside the grace period ends the wait.
func TestVerificationDeadlineEndsTheGracePeriod(t *testing.T) {
	pod := fixturePod()
	pod.Finalizers = []string{"example.invalid/hold"}
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

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 0 || res.RequeueAfter != 20*time.Second {
		t.Fatalf("%d destruction requests, requeue %s: want the instance kept and a wake at the deadline in 20s", cloud.deleteCalls, res.RequeueAfter)
	}

	r.now = func() time.Time { return deadline }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 {
		t.Fatalf("%d destruction requests at the verification deadline, want 1", cloud.deleteCalls)
	}
	got := getPod(t, r, pod)
	if got.Status.Phase != corev1.PodFailed || got.Status.Reason != verificationTimeoutReason {
		t.Fatalf("Pod is %s/%s at its verification deadline, want Failed/%s", got.Status.Phase, got.Status.Reason, verificationTimeoutReason)
	}
	if !controllerutil.ContainsFinalizer(got, finalizer) {
		t.Fatal("Pod released before its instance's destruction was confirmed")
	}

	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if got := getPod(t, r, pod); controllerutil.ContainsFinalizer(got, finalizer) || got.Status.Reason != verificationTimeoutReason {
		t.Fatalf("after destruction: finalizer held=%t, reason %q", controllerutil.ContainsFinalizer(got, finalizer), got.Status.Reason)
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
		end, held := r.graceEnd(pod, rec)
		if got := end.Sub(deleted); !held || got != time.Duration(tc.want)*time.Second {
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
