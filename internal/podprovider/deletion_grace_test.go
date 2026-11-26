package podprovider

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
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
	if res.RequeueAfter != pollInterval {
		t.Fatalf("requeued after %s with 30s of the grace period left, want another look in %s", res.RequeueAfter, pollInterval)
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

// The mark is cleared before the send. A Pod deleted while it is being
// cleared is caught by the check that follows, and nothing was sent.
func TestDeletionDoesNotWaitWhenTheLastCheckStoppedTheSend(t *testing.T) {
	pod := fixturePod()
	r, cloud, guest := fixture(t, pod)
	inner := r.client.(client.WithWatch)
	deleted := false
	r.client = interceptor.NewClient(inner, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		var rec record
		if secret, ok := obj.(*corev1.Secret); ok && !deleted && decode(secret.Data["state.json"], &rec) == nil && len(rec.Assignment) != 0 && !rec.AssignmentUnsent {
			deleted = true
			if err := c.Delete(ctx, getPod(t, r, pod)); err != nil {
				t.Fatal(err)
			}
		}
		return c.Update(ctx, obj, opts...)
	}})
	for range 8 {
		if deleted {
			break
		}
		_ = reconcile(t, r, pod)
	}
	if !deleted || guest.sends != 0 {
		t.Fatalf("fixture: want the Pod deleted before any send, got deleted=%t and %d sends", deleted, guest.sends)
	}
	end := getPod(t, r, pod).DeletionTimestamp.Time
	r.now = func() time.Time { return end.Add(-30 * time.Second) }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if guest.sends != 0 || cloud.deleteCalls != 1 {
		t.Fatalf("%d sends, %d destruction requests for a Pod whose send the last check stopped, want 0 and 1", guest.sends, cloud.deleteCalls)
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

// A status the API server refused is published again before the Pod is
// released, so a missed deadline is not lost with the first attempt.
func TestDeletionPublishesTheMissedDeadlineAfterARefusedAttempt(t *testing.T) {
	pod := fixturePod()
	pod.Finalizers = []string{"example.invalid/hold"}
	// No application port, so no endpoints annotation whose withdrawal would
	// reread the Pod between the two attempts.
	pod.Spec.Containers[0].Ports = nil
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
	r.now = func() time.Time { return end.Add(time.Hour) }
	cloud.in.Status = "terminated"
	refused := false
	r.client = interceptor.NewClient(r.client.(client.WithWatch), interceptor.Funcs{SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
		if !refused {
			refused = true
			return errors.New("status patch refused")
		}
		return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
	}})
	for range 3 {
		_ = reconcile(t, r, pod)
	}
	got := getPod(t, r, pod)
	if !refused || controllerutil.ContainsFinalizer(got, finalizer) {
		t.Fatalf("fixture: refused=%t, finalizer held=%t", refused, controllerutil.ContainsFinalizer(got, finalizer))
	}
	if got.Status.Phase != corev1.PodFailed || got.Status.Reason != verificationTimeoutReason {
		t.Fatalf("Pod released as %s/%q, want Failed/%s", got.Status.Phase, got.Status.Reason, verificationTimeoutReason)
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
	// Sooner than the next look, so that the deadline alone sets the wake.
	deadline := end.Add(-26 * time.Second)
	rec.VerificationDeadline = &deadline
	if err := r.save(context.Background(), rec, secret); err != nil {
		t.Fatal(err)
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 0 || res.RequeueAfter != 4*time.Second {
		t.Fatalf("%d destruction requests, requeue %s: want the instance kept and a wake at the deadline in 4s", cloud.deleteCalls, res.RequeueAfter)
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

// heldPod is a running Pod deleted with 30s of its grace period left, kept
// by a second finalizer so that its last status can be read.
func heldPod(t *testing.T) (*corev1.Pod, *Reconciler, *fakeCloud, *fakeGuest) {
	t.Helper()
	pod := fixturePod()
	pod.Finalizers = []string{"example.invalid/hold"}
	r, cloud, guest := fixture(t, pod)
	runToRunning(t, r, pod)
	deleteWithGraceLeft(t, r, pod, 30*time.Second)
	return pod, r, cloud, guest
}

// The grace period is for the Pod's containers to stop. Once the guest
// reports that they have, nothing is left to wait for.
func TestDeletionEndsTheWaitWhenTheGuestReportsThePodEnded(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed} {
		t.Run(string(phase), func(t *testing.T) {
			pod, r, cloud, guest := heldPod(t)
			r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
				p := fixtureProjection(rec)
				p.Status.Phase = phase
				p.Status.ContainerStatuses[0].State = &podstatus.ContainerState{Terminated: &podstatus.ContainerTerminated{}}
				return p, nil
			}
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			if cloud.deleteCalls != 1 {
				t.Fatalf("%d destruction requests once the guest reported the Pod %s, want 1", cloud.deleteCalls, phase)
			}
			if got := getPod(t, r, pod).Status; got.Phase != phase || got.Reason != "" {
				t.Fatalf("Pod is %s/%q, want the guest's %s", got.Phase, got.Reason, phase)
			}
			if rec := getRecord(t, r, pod); rec.TerminalStatus == nil || rec.TerminalStatus.Phase != phase {
				t.Fatalf("record keeps %+v as the Pod's last status, want %s", rec.TerminalStatus, phase)
			}
			if guest.sends != 1 || cloud.createCalls != 1 {
				t.Fatalf("%d sends and %d creates, want the 1 of each the launch made", guest.sends, cloud.createCalls)
			}
		})
	}
}

// An instance that stopped, restarted or is not the Pod's own runs no
// containers of the Pod to wait for.
func TestDeletionEndsTheWaitWhenTheInstanceEnded(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*fakeCloud)
	}{
		{"failed", "InstanceEnded", func(c *fakeCloud) { c.in.Status = "failed" }},
		{"stopped", "InstanceEnded", func(c *fakeCloud) { c.in.Status = "stopped" }},
		{"terminated", "InstanceEnded", func(c *fakeCloud) { c.in.Status = "terminated" }},
		{"gone", "InstanceGone", func(c *fakeCloud) { c.in = nil }},
		{"rebooted", "GuestRebooted", func(c *fakeCloud) { c.in.Boot.Count = 2 }},
		{"another image", "InstanceIdentityMismatch", func(c *fakeCloud) { c.in.Image.Version = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, r, cloud, guest := heldPod(t)
			reads := guest.reads
			tc.change(cloud)
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			got := getPod(t, r, pod)
			if got.Status.Phase != corev1.PodFailed || got.Status.Reason != tc.reason {
				t.Fatalf("Pod is %s/%q inside its grace period, want Failed/%s", got.Status.Phase, got.Status.Reason, tc.reason)
			}
			// An instance Cloud already ended needs no request; the Pod is released.
			if cloud.deleteCalls != 1 && controllerutil.ContainsFinalizer(got, finalizer) {
				t.Fatal("Pod still held with no destruction requested once its instance had ended")
			}
			if guest.reads != reads {
				t.Fatal("guest read through an instance that had ended")
			}
		})
	}
}

// A Pod still running is held, and looked at again within the poll interval
// or when the wait ends, whichever is sooner. Looking changes nothing.
func TestDeletionLooksAgainWhileThePodRuns(t *testing.T) {
	for _, tc := range []struct{ left, want time.Duration }{
		{30 * time.Second, pollInterval},
		{4 * time.Second, 4 * time.Second},
	} {
		t.Run(tc.left.String(), func(t *testing.T) {
			pod, r, cloud, guest := heldPod(t)
			end := getPod(t, r, pod).DeletionTimestamp.Time
			r.now = func() time.Time { return end.Add(-tc.left) }
			before, reads := getRecord(t, r, pod), guest.reads
			if got := reconcileResult(t, r, pod).RequeueAfter; got != tc.want {
				t.Fatalf("requeued after %s with %s left, want %s", got, tc.left, tc.want)
			}
			if guest.reads != reads+1 {
				t.Fatalf("%d guest reads while held, want 1", guest.reads-reads)
			}
			if cloud.deleteCalls != 0 || cloud.createCalls != 1 || guest.sends != 1 {
				t.Fatalf("%d destruction requests, %d creates, %d sends for a running Pod inside its grace period, want 0, 1 and 1", cloud.deleteCalls, cloud.createCalls, guest.sends)
			}
			if after := getRecord(t, r, pod); !reflect.DeepEqual(before, after) {
				t.Fatal("looking at a held Pod changed its record")
			}
			if got := getPod(t, r, pod).Status.Phase; got != corev1.PodRunning {
				t.Fatalf("Pod is %s while held, want Running", got)
			}
		})
	}
}

// A read that fails shows nothing about the Pod, so it stays held. Nothing is
// sent to the guest and no verification deadline starts.
func TestDeletionStaysHeldWhenAReadFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(*Reconciler, *fakeCloud)
		want time.Duration
	}{
		{"cloud unavailable", func(_ *Reconciler, c *fakeCloud) {
			c.get = func(string) (*instance, error) { return nil, errors.New("cloud unavailable") }
		}, pollInterval},
		{"cloud rate limit", func(_ *Reconciler, c *fakeCloud) {
			c.get = func(string) (*instance, error) {
				return nil, &cloudProblem{status: http.StatusTooManyRequests, retryAfter: 20 * time.Second}
			}
		}, 20 * time.Second},
		{"cloud rate limit past the wait", func(_ *Reconciler, c *fakeCloud) {
			c.get = func(string) (*instance, error) {
				return nil, &cloudProblem{status: http.StatusTooManyRequests, retryAfter: time.Hour}
			}
		}, 30 * time.Second},
		{"instance starting", func(_ *Reconciler, c *fakeCloud) { c.in.Status = "provisioning" }, pollInterval},
		{"answer naming no instance", func(_ *Reconciler, c *fakeCloud) {
			c.get = func(string) (*instance, error) { return &instance{}, nil }
		}, pollInterval},
		{"guest unreachable", func(r *Reconciler, _ *fakeCloud) {
			r.guest = func(context.Context, *record, string) (podstatus.PodProjection, error) {
				return podstatus.PodProjection{}, errors.New("attestation failed")
			}
		}, pollInterval},
		{"status of another Pod", func(r *Reconciler, _ *fakeCloud) {
			r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
				p := fixtureProjection(rec)
				p.Metadata.UID, p.Status.Phase = "another", corev1.PodSucceeded
				return p, nil
			}
		}, pollInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, r, cloud, guest := heldPod(t)
			before := getRecord(t, r, pod)
			tc.fail(r, cloud)
			if got := reconcileResult(t, r, pod).RequeueAfter; got != tc.want {
				t.Fatalf("requeued after %s, want %s", got, tc.want)
			}
			if cloud.deleteCalls != 0 || cloud.createCalls != 1 || guest.sends != 1 {
				t.Fatalf("%d destruction requests, %d creates, %d sends after a read that showed nothing, want 0, 1 and 1", cloud.deleteCalls, cloud.createCalls, guest.sends)
			}
			if after := getRecord(t, r, pod); !reflect.DeepEqual(before, after) {
				t.Fatal("a failed read changed the held Pod's record")
			}
			if got := getPod(t, r, pod).Status.Phase; got != corev1.PodRunning {
				t.Fatalf("Pod is %s after a failed read, want its last verified Running", got)
			}
		})
	}
}

// A look takes no longer than the wait that is left, so a guest that never
// answers cannot keep the instance past the grace period.
func TestDeletionLookEndsWithTheWait(t *testing.T) {
	pod, r, cloud, _ := heldPod(t)
	end := getPod(t, r, pod).DeletionTimestamp.Time
	r.now = func() time.Time { return end.Add(-50 * time.Millisecond) }
	r.guest = func(ctx context.Context, _ *record, _ string) (podstatus.PodProjection, error) {
		select {
		case <-ctx.Done():
			return podstatus.PodProjection{}, ctx.Err()
		case <-time.After(30 * time.Second):
			return podstatus.PodProjection{}, errors.New("the look outlived the wait")
		}
	}
	started := time.Now()
	res := reconcileResult(t, r, pod)
	if took := time.Since(started); took > 10*time.Second {
		t.Fatalf("look took %s with 50ms of the wait left", took)
	}
	if cloud.deleteCalls != 0 || res.RequeueAfter != 50*time.Millisecond {
		t.Fatalf("%d destruction requests, requeue %s: want the Pod held and a wake when the wait ends", cloud.deleteCalls, res.RequeueAfter)
	}
}

// A look takes time. When the wait ended during it, the instance is
// destroyed in the same pass, and a verification deadline that ended it is
// still reported.
func TestDeletionDoesNotWaitAgainWhenTheWaitEndedDuringALook(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline time.Duration // before the end of the grace period; 0 for none
		reason   string
	}{
		{"grace period", 0, ""},
		{"verification deadline", 10 * time.Second, verificationTimeoutReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, r, cloud, _ := heldPod(t)
			end := getPod(t, r, pod).DeletionTimestamp.Time
			if tc.deadline != 0 {
				rec, secret, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID)))
				if err != nil {
					t.Fatal(err)
				}
				deadline := end.Add(-tc.deadline)
				rec.VerificationDeadline = &deadline
				if err := r.save(context.Background(), rec, secret); err != nil {
					t.Fatal(err)
				}
			}
			r.guest = func(context.Context, *record, string) (podstatus.PodProjection, error) {
				r.now = func() time.Time { return end }
				return podstatus.PodProjection{}, errors.New("no answer in time")
			}
			if res := reconcileResult(t, r, pod); cloud.deleteCalls != 1 {
				t.Fatalf("%d destruction requests, requeue %s: want the instance destroyed once the wait ended during the look", cloud.deleteCalls, res.RequeueAfter)
			}
			if got := getPod(t, r, pod).Status.Reason; got != tc.reason {
				t.Fatalf("Pod reason is %q, want %q", got, tc.reason)
			}
		})
	}
}

// An instance under the Pod's identity that another launch owns ends the Pod
// as it does while the Pod runs, and is not the provider's to destroy.
func TestDeletionEndsTheWaitForAnInstanceItDoesNotOwn(t *testing.T) {
	pod, r, cloud, _ := heldPod(t)
	cloud.in.Labels = nil
	if err := reconcile(t, r, pod); !errors.Is(err, errForeignInstance) {
		t.Fatalf("reconcile returned %v, want the refusal to destroy another launch's instance", err)
	}
	if got := getPod(t, r, pod).Status; got.Phase != corev1.PodFailed || got.Reason != "InstanceIdentityMismatch" {
		t.Fatalf("Pod is %s/%q, want Failed/InstanceIdentityMismatch", got.Phase, got.Reason)
	}
	if cloud.deleteCalls != 0 {
		t.Fatal("destruction requested for an instance another launch owns")
	}
}

// A Pod is released with its endpoints withdrawn: they named an instance
// that no longer exists. A withdrawal the API server refused when the Pod
// ended is made again before the release.
func TestDeletionWithdrawsEndpointsBeforeReleasingThePod(t *testing.T) {
	pod, r, cloud, _ := heldPod(t)
	if getPod(t, r, pod).Annotations[endpointsAnnotation] == "" {
		t.Fatal("fixture: running Pod publishes no endpoints")
	}
	cloud.in.Status = "failed"
	refused := false
	r.client = interceptor.NewClient(r.client.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*corev1.Pod); ok && !refused {
			refused = true
			return errors.New("annotation patch refused")
		}
		return c.Patch(ctx, obj, patch, opts...)
	}})
	for range 3 {
		_ = reconcile(t, r, pod)
		cloud.in.Status = "terminated"
	}
	got := getPod(t, r, pod)
	if !refused || controllerutil.ContainsFinalizer(got, finalizer) {
		t.Fatalf("fixture: refused=%t, finalizer held=%t", refused, controllerutil.ContainsFinalizer(got, finalizer))
	}
	if got.Annotations[endpointsAnnotation] != "" {
		t.Fatalf("Pod released still advertising %s", got.Annotations[endpointsAnnotation])
	}
}

// A verification deadline that passes while the guest's answer is read is
// reported, as it is for a Pod that is not being deleted: the answer came
// too late to be the Pod's last status.
func TestDeletionReportsADeadlineThatPassedDuringALook(t *testing.T) {
	pod, r, cloud, _ := heldPod(t)
	end := getPod(t, r, pod).DeletionTimestamp.Time
	rec, secret, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := end.Add(-10 * time.Second)
	rec.VerificationDeadline = &deadline
	if err := r.save(context.Background(), rec, secret); err != nil {
		t.Fatal(err)
	}
	r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
		r.now = func() time.Time { return deadline }
		p := fixtureProjection(rec)
		p.Status.Phase = corev1.PodSucceeded
		p.Status.ContainerStatuses[0].State = &podstatus.ContainerState{Terminated: &podstatus.ContainerTerminated{}}
		return p, nil
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if got := getPod(t, r, pod).Status; got.Phase != corev1.PodFailed || got.Reason != verificationTimeoutReason || cloud.deleteCalls != 1 {
		t.Fatalf("Pod is %s/%q with %d destruction requests, want Failed/%s and 1", got.Phase, got.Reason, cloud.deleteCalls, verificationTimeoutReason)
	}
}

// The instance may already be gone when the withdrawal is refused, so that
// the same pass reaches the release. The Pod is kept until it is withdrawn.
func TestDeletionKeepsThePodUntilItsEndpointsAreWithdrawn(t *testing.T) {
	pod, r, cloud, _ := heldPod(t)
	cloud.in.Status = "terminated"
	refusing, refused := true, 0
	r.client = interceptor.NewClient(r.client.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		// Only the withdrawal is refused: the patch that releases the Pod
		// would go through.
		if data, err := patch.Data(obj); err == nil && refusing && bytes.Contains(data, []byte(endpointsAnnotation)) {
			refused++
			return errors.New("annotation patch refused")
		}
		return c.Patch(ctx, obj, patch, opts...)
	}})
	_ = reconcile(t, r, pod)
	got := getPod(t, r, pod)
	if refused != 2 {
		t.Fatalf("%d withdrawals refused, want the one when the Pod ended and the one before its release", refused)
	}
	if got.Annotations[endpointsAnnotation] == "" || !controllerutil.ContainsFinalizer(got, finalizer) {
		t.Fatalf("endpoints %q, finalizer held=%t: want the Pod kept while it still advertises its endpoints", got.Annotations[endpointsAnnotation], controllerutil.ContainsFinalizer(got, finalizer))
	}
	refusing = false
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if got := getPod(t, r, pod); got.Annotations[endpointsAnnotation] != "" || controllerutil.ContainsFinalizer(got, finalizer) {
		t.Fatalf("after the retry: endpoints %q, finalizer held=%t, want withdrawn and released", got.Annotations[endpointsAnnotation], controllerutil.ContainsFinalizer(got, finalizer))
	}
}

// countGets counts the Cloud reads of the Pod's instance from here on.
func countGets(cloud *fakeCloud, answer func() (*instance, error)) *int {
	n := new(int)
	cloud.get = func(string) (*instance, error) {
		*n++
		if answer != nil {
			return answer()
		}
		return cloud.in, nil
	}
	return n
}

// The wait Cloud asked for holds however the next pass was triggered: a Pod
// update inside it is not another read. The wait ending still ends the hold.
func TestDeletionDoesNotLookAgainBeforeCloudAllows(t *testing.T) {
	pod, r, cloud, _ := heldPod(t)
	end := getPod(t, r, pod).DeletionTimestamp.Time
	at := func(left time.Duration) { r.now = func() time.Time { return end.Add(-left) } }
	gets := countGets(cloud, func() (*instance, error) {
		return nil, &cloudProblem{status: http.StatusTooManyRequests, retryAfter: 20 * time.Second}
	})
	if got := reconcileResult(t, r, pod).RequeueAfter; *gets != 1 || got != 20*time.Second {
		t.Fatalf("%d reads, requeue %s: want 1 read and the 20s Cloud asked for", *gets, got)
	}
	at(25 * time.Second)
	if got := reconcileResult(t, r, pod).RequeueAfter; *gets != 1 || got != 15*time.Second {
		t.Fatalf("%d reads, requeue %s for a pass 5s into a 20s wait: want no new read and the 15s left", *gets, got)
	}
	at(10 * time.Second)
	if reconcileResult(t, r, pod); *gets != 2 {
		t.Fatalf("%d reads once the wait Cloud asked for had passed, want 2", *gets)
	}
	at(0)
	cloud.get = nil
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 1 {
		t.Fatalf("%d destruction requests when the grace period ended inside Cloud's wait, want 1", cloud.deleteCalls)
	}
}

// Looks are a poll interval apart from start to start, however long one
// takes and however the next pass was triggered.
func TestDeletionLooksAPollIntervalApart(t *testing.T) {
	for _, tc := range []struct {
		name       string
		took, want time.Duration
	}{
		{"quick look", 0, pollInterval},
		{"slow look", 7 * time.Second, 3 * time.Second},
		{"look longer than the interval", 12 * time.Second, minLookGap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, r, cloud, _ := heldPod(t)
			end := getPod(t, r, pod).DeletionTimestamp.Time
			r.now = func() time.Time { return end.Add(-60 * time.Second) }
			gets := countGets(cloud, func() (*instance, error) {
				r.now = func() time.Time { return end.Add(-60*time.Second + tc.took) }
				return cloud.in, nil
			})
			if got := reconcileResult(t, r, pod).RequeueAfter; *gets != 1 || got != tc.want {
				t.Fatalf("%d reads, requeue %s after a look that took %s: want 1 and %s", *gets, got, tc.took, tc.want)
			}
		})
	}
	t.Run("pass between looks", func(t *testing.T) {
		pod, r, cloud, _ := heldPod(t)
		end := getPod(t, r, pod).DeletionTimestamp.Time
		gets := countGets(cloud, nil)
		reconcileResult(t, r, pod)
		r.now = func() time.Time { return end.Add(-26 * time.Second) }
		if got := reconcileResult(t, r, pod).RequeueAfter; *gets != 1 || got != 6*time.Second {
			t.Fatalf("%d reads, requeue %s for a pass 4s after a look: want no new read and the 6s to the next", *gets, got)
		}
	})
}

// Cloud's wait runs from its answer, and a look that outlasted the interval
// is followed by another no sooner than the minimum gap, whatever triggers
// the pass. Neither is kept past the end of the wait.
func TestDeletionSpacesLooksFromWhenTheLastEnded(t *testing.T) {
	for _, tc := range []struct {
		name              string
		left, took, retry time.Duration
		want              time.Duration
	}{
		{"cloud's wait after a slow answer", 60 * time.Second, 5 * time.Second, 20 * time.Second, 20 * time.Second},
		{"look longer than the interval", 60 * time.Second, 12 * time.Second, 0, minLookGap},
		{"look just short of the interval", 60 * time.Second, 9750 * time.Millisecond, 0, 250 * time.Millisecond},
		{"cloud's wait past the end of the hold", 30 * time.Second, 0, time.Hour, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, r, cloud, _ := heldPod(t)
			end := getPod(t, r, pod).DeletionTimestamp.Time
			after := end.Add(-tc.left + tc.took)
			r.now = func() time.Time { return end.Add(-tc.left) }
			gets := countGets(cloud, func() (*instance, error) {
				r.now = func() time.Time { return after }
				if tc.retry != 0 {
					return nil, &cloudProblem{status: http.StatusTooManyRequests, retryAfter: tc.retry}
				}
				return cloud.in, nil
			})
			if got := reconcileResult(t, r, pod).RequeueAfter; got != tc.want {
				t.Fatalf("requeued after %s, want %s", got, tc.want)
			}
			if next := r.nextLook[pod.UID]; next != after.Add(tc.want) || next.After(end) {
				t.Fatalf("next look kept as %s after the look ended, want %s and no later than the end of the hold", next.Sub(after), tc.want)
			}
			// A pass triggered just short of that time is not another look.
			r.now = func() time.Time { return after.Add(tc.want - time.Millisecond) }
			if reconcileResult(t, r, pod); *gets != 1 {
				t.Fatalf("%d reads for a pass before the next look was due, want 1", *gets)
			}
		})
	}
}
