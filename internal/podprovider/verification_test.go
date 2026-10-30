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
	restarted := &Reconciler{client: r.client, cfg: &next, cloud: cloud, guest: refusingGuest, now: r.now}
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
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
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

func TestLegacyRecordReceivesOnlyOneDurableUpgradeWindow(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	rec, secret, err := r.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	rec.VerificationTimeoutSeconds, rec.VerificationDeadline = 0, nil
	rec.CreatedAt = time.Now().Add(-time.Hour)
	if err := r.save(t.Context(), rec, secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	r.guest = refusingGuest
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	deadline := *getRecord(t, r, pod).VerificationDeadline
	if !deadline.Equal(now.Add(10 * time.Minute)) {
		t.Fatal("legacy upgrade received no grace window")
	}
	now = now.Add(time.Minute)
	r.cfg.VerificationTimeoutSeconds = 30
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if !getRecord(t, r, pod).VerificationDeadline.Equal(deadline) {
		t.Fatal("legacy migration repeated")
	}
}

type verificationCloud struct {
	cloudAPI
	get func(context.Context, string) (*instance, error)
	del func(context.Context, string) error
}

func (c *verificationCloud) Get(ctx context.Context, id string) (*instance, error) {
	if c.get != nil {
		return c.get(ctx, id)
	}
	return c.cloudAPI.Get(ctx, id)
}
func (c *verificationCloud) Delete(ctx context.Context, id string) error {
	if c.del != nil {
		return c.del(ctx, id)
	}
	return c.cloudAPI.Delete(ctx, id)
}

func TestVerificationBudgetCancelsCloudAndGuestCalls(t *testing.T) {
	for _, kind := range []string{"cloud", "guest"} {
		t.Run(kind, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			rec, secret, err := r.loadRecord(t.Context(), identityKey(r.cfg.ProviderID, string(pod.UID)))
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(500 * time.Millisecond)
			rec.VerificationDeadline = &deadline
			if err := r.save(t.Context(), rec, secret); err != nil {
				t.Fatal(err)
			}
			entered := false
			if kind == "cloud" {
				blocked := false
				r.cloud = &verificationCloud{cloudAPI: cloud, get: func(ctx context.Context, id string) (*instance, error) {
					if !blocked {
						blocked = true
						entered = true
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return cloud.Get(ctx, id)
				}}
			} else {
				r.guest = func(ctx context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
					entered = true
					<-ctx.Done()
					return fixtureProjection(rec), nil
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
			if err != nil || ctx.Err() != nil || !entered {
				t.Fatalf("network call did not exercise its verification budget: %v, entered=%t", err, entered)
			}
			assertVerificationFailed(t, r, pod)
		})
	}
}

func TestTerminalCleanupSurvivesPublicationAndCloudFailures(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	r.guest = refusingGuest
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	now := *getRecord(t, r, pod).VerificationDeadline
	r.now = func() time.Time { return now }
	original := r.client
	watching, ok := original.(client.WithWatch)
	if !ok {
		t.Fatal("fixture client lacks watch support")
	}
	r.client = interceptor.NewClient(watching, interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
		return errors.New("status write unavailable")
	}})
	deleteAttempts := 0
	r.cloud = &verificationCloud{cloudAPI: cloud, del: func(context.Context, string) error { deleteAttempts++; return errors.New("Cloud delete unavailable") }}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("publication and cleanup failures hidden")
	}
	rec := getRecord(t, r, pod)
	if deleteAttempts != 1 || rec.TerminalStatus == nil || !rec.DeleteRequested || rec.Deleted {
		t.Fatal("publication failure stranded the VM or lost cleanup intent")
	}
	r.client, r.cloud = original, cloud
	r.ownsNode = func(context.Context) error { t.Fatal("terminal cleanup waited for node ownership"); return nil }
	r.guest = func(context.Context, *record, string) (podstatus.PodProjection, error) {
		t.Fatal("terminal cleanup read the guest")
		return podstatus.PodProjection{}, nil
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	assertVerificationFailed(t, r, pod)
	cloud.in.Status = "terminated"
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if !getRecord(t, r, pod).Deleted || cloud.createCalls != 1 || len(getPod(t, r, pod).Finalizers) == 0 {
		t.Fatal("terminal cleanup lost UID/finalizer authority")
	}
}

func TestTimeoutCleanupRefusesForeignKnownInstanceResponses(t *testing.T) {
	for _, kind := range []string{"id", "labels", "terminated-id", "terminated-labels"} {
		t.Run(kind, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			r.guest = refusingGuest
			if err := reconcile(t, r, pod); err != nil {
				t.Fatal(err)
			}
			rec := getRecord(t, r, pod)
			now := *rec.VerificationDeadline
			r.now = func() time.Time { return now }
			foreign := instanceFor(rec.Request)
			if kind == "id" || kind == "terminated-id" {
				foreign.ID = "i-foreign"
			} else {
				foreign.Labels["podcvm-uid"] = "foreign"
			}
			if kind == "terminated-id" || kind == "terminated-labels" {
				foreign.Status = "terminated"
			}
			r.cloud = &verificationCloud{cloudAPI: cloud, get: func(context.Context, string) (*instance, error) { return foreign, nil }}
			if err := reconcile(t, r, pod); err == nil {
				t.Fatal("foreign cleanup response accepted")
			}
			if cloud.deleteCalls != 0 || getRecord(t, r, pod).Deleted {
				t.Fatal("foreign VM deleted or cleanup falsely confirmed")
			}
			assertVerificationFailed(t, r, pod)
		})
	}
}

func TestVerificationTimeoutConfigurationBounds(t *testing.T) {
	for _, seconds := range []int64{-1, 0, 29, 30, 600, 86400, 86401} {
		cfg := fixtureConfig(t)
		cfg.VerificationTimeoutSeconds = seconds
		err := cfg.validate()
		valid := seconds == 0 || seconds >= 30 && seconds <= 86400
		if (err == nil) != valid {
			t.Fatalf("timeout %d: %v", seconds, err)
		}
		if seconds == 0 && cfg.VerificationTimeoutSeconds != 600 {
			t.Fatal("missing default")
		}
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

func TestNodeOwnershipFailureCannotExtendVerificationDeadline(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	r.guest = refusingGuest
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	deadline := *getRecord(t, r, pod).VerificationDeadline
	now := deadline.Add(-time.Second)
	r.now = func() time.Time { return now }
	r.ownsNode = func(context.Context) error { now = deadline; return errors.New("node registration unavailable") }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	assertVerificationFailed(t, r, pod)
	if cloud.deleteCalls != 1 || cloud.createCalls != 1 {
		t.Fatal("node ownership loss blocked cleanup or launched another VM")
	}
}

func TestCleanupNeverAcceptsAnEmptyCloudIdentity(t *testing.T) {
	for _, status := range []string{"running", "terminated"} {
		pod := fixturePod()
		r, cloud := fixtureReconciler(t, pod)
		rec, secret, err := r.ensureRecord(t.Context(), pod)
		if err != nil {
			t.Fatal(err)
		}
		cloud.in = instanceFor(rec.Request)
		cloud.in.ID, cloud.in.Status = "", status
		if done, err := r.removeInstance(t.Context(), rec, secret); done || err == nil {
			t.Fatal("empty cleanup identity accepted")
		}
		if cloud.deleteCalls != 0 || getRecord(t, r, pod).Deleted {
			t.Fatal("empty identity discarded cleanup authority")
		}
	}
}
