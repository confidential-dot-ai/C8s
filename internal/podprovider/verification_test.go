package podprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

func refusingGuest(context.Context, *record, string) (podstatus.PodProjection, error) {
	return podstatus.PodProjection{}, errors.New("unverifiable guest")
}

func assertVerificationFailed(t *testing.T, r *Reconciler, pod *corev1.Pod) {
	t.Helper()
	got := getPod(t, r, pod)
	rec := getRecord(t, r, pod)
	if got.Status.Phase != corev1.PodFailed || got.Status.Reason != verificationTimeoutReason || rec.TerminalStatus == nil || rec.TerminalStatus.Reason != verificationTimeoutReason || got.Annotations[endpointsAnnotation] != "" {
		t.Fatal("verification expiry was not durably terminal with endpoints withdrawn")
	}
	for _, c := range got.Status.Conditions {
		if (c.Type == corev1.PodReady || c.Type == corev1.ContainersReady) && c.Status != corev1.ConditionFalse {
			t.Fatal("expired guest retained readiness")
		}
	}
}

func TestVerificationDeadlineSurvivesRestartAndRejectsLateRecovery(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	now := time.Now()
	r.now = func() time.Time { return now }
	r.guest = refusingGuest
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	before := getRecord(t, r, pod)
	deadline := *before.VerificationDeadline
	if !deadline.Equal(before.CreatedAt.Add(10 * time.Minute)) {
		t.Fatal("initial budget did not begin with the persisted intent")
	}
	next := *r.cfg
	next.VerificationTimeoutSeconds = 86400
	restarted := &Reconciler{client: r.client, cfg: &next, cloud: cloud, guest: refusingGuest, assignment: r.assignment, now: r.now}
	now = deadline.Add(-time.Second)
	result, err := restarted.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	if err != nil || result.RequeueAfter != time.Second || getPod(t, r, pod).Status.Phase == corev1.PodFailed {
		t.Fatalf("deadline/backoff changed after restart: %+v %v", result, err)
	}
	if got := getRecord(t, r, pod); got.VerificationTimeoutSeconds != 600 || !got.VerificationDeadline.Equal(deadline) {
		t.Fatal("restart or new configuration refreshed the frozen budget")
	}
	now = deadline
	restarted.guest = func(context.Context, *record, string) (podstatus.PodProjection, error) {
		t.Fatal("expired intent reached the guest")
		return podstatus.PodProjection{}, nil
	}
	if err := reconcile(t, restarted, pod); err != nil {
		t.Fatal(err)
	}
	assertVerificationFailed(t, restarted, pod)
	cloud.in.Status = "terminated"
	if err := reconcile(t, restarted, pod); err != nil {
		t.Fatal(err)
	}
	if cloud.createCalls != 1 || !getRecord(t, r, pod).Deleted {
		t.Fatal("expired Pod was recreated or termination was not retained")
	}
}

func TestLateOrCancelledVerifiedReplyCannotPublishReady(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "leader-cancelled"}[cancelled], func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			now := time.Now()
			r.now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
				if cancelled {
					cancel()
				} else {
					now = *rec.VerificationDeadline
				}
				return fixtureProjection(rec), nil
			}
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
			if cancelled {
				if !errors.Is(err, context.Canceled) || cloud.deleteCalls != 0 {
					t.Fatalf("cancelled leader continued: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertVerificationFailed(t, r, pod)
			}
			if getPod(t, r, pod).Annotations[endpointsAnnotation] != "" {
				t.Fatal("late reply published endpoints")
			}
			for _, c := range getPod(t, r, pod).Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					t.Fatal("late reply published Ready")
				}
			}
		})
	}
}

func TestVerifiedPendingAndTransientRecoveryResetOnlyTheOutage(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	now := time.Now()
	r.now = func() time.Time { return now }
	good := r.guest
	runToRunning(t, r, pod)
	if getRecord(t, r, pod).VerificationDeadline != nil {
		t.Fatal("verified status retained initial deadline")
	}
	r.guest = refusingGuest
	now = now.Add(time.Hour)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	deadline := *getRecord(t, r, pod).VerificationDeadline
	r.guest = func(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
		p, err := good(ctx, rec, address)
		p.Status.Phase = corev1.PodPending
		p.Status.Conditions[0].Status = corev1.ConditionFalse
		p.Status.ContainerStatuses[0].Ready = false
		return p, err
	}
	now = deadline.Add(-time.Second)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	now = deadline.Add(24 * time.Hour)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if getRecord(t, r, pod).VerificationDeadline != nil || getPod(t, r, pod).Status.Phase != corev1.PodPending || cloud.deleteCalls != 0 {
		t.Fatal("valid Pending was treated as unverifiable")
	}
	r.guest = refusingGuest
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if !getRecord(t, r, pod).VerificationDeadline.Equal(now.Add(10 * time.Minute)) {
		t.Fatal("new outage inherited the expired previous window")
	}
}

func TestVerificationStateWriteFailureCannotGrantReadinessOrDelete(t *testing.T) {
	for _, outcome := range []string{"verified", "expired"} {
		t.Run(outcome, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			good := r.guest
			r.guest = refusingGuest
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			if outcome == "verified" {
				r.guest = good
			} else {
				now := *getRecord(t, r, pod).VerificationDeadline
				r.now = func() time.Time { return now }
			}
			original := r.client
			watching, ok := original.(client.WithWatch)
			if !ok {
				t.Fatal("fixture client lacks watch support")
			}
			r.client = interceptor.NewClient(watching, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, secret := obj.(*corev1.Secret); secret {
					return errors.New("record write unavailable")
				}
				return c.Update(ctx, obj, opts...)
			}})
			if err := reconcile(t, r, pod); err == nil {
				t.Fatal("durable state failure hidden")
			}
			if getPod(t, r, pod).Annotations[endpointsAnnotation] != "" || cloud.deleteCalls != 0 || getRecord(t, r, pod).TerminalStatus != nil {
				t.Fatal("uncommitted transition granted endpoints or deleted the VM")
			}
			for _, c := range getPod(t, r, pod).Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					t.Fatal("uncommitted verification granted Ready")
				}
			}
			r.client = original
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			if outcome == "expired" {
				assertVerificationFailed(t, r, pod)
			}
		})
	}
}
