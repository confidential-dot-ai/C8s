//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

// cloudDelayedGuest delays a real verified response, including beyond the
// verification child context's deadline. Its separate abort bounds shutdown.
type cloudDelayedGuest struct {
	read                guestReader
	uid                 types.UID
	deadline, deliverAt time.Time
	abort               context.Context
	captured, delivered chan time.Time
}

func (g *cloudDelayedGuest) readGuest(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	callCtx, cancel := context.WithCancel(ctx)
	stopAbort := context.AfterFunc(g.abort, cancel)
	defer stopAbort()
	defer cancel()
	projection, err := g.read(callCtx, rec, address)
	if err != nil || rec.UID != g.uid {
		return projection, err
	}
	verifiedAt := time.Now()
	if !verifiedAt.Before(g.deadline) {
		return podstatus.PodProjection{}, errors.New("guest verification did not finish before the frozen deadline")
	}
	select {
	case g.captured <- verifiedAt:
	default:
		return podstatus.PodProjection{}, errors.New("unexpected repeated delayed guest verification")
	}
	// Ignore only the child's verification deadline after real verification has
	// succeeded, modeling a late successful callback without fabricating status.
	if err := cloudPause(g.abort, time.Until(g.deliverAt)); err != nil {
		return podstatus.PodProjection{}, err
	}
	g.delivered <- time.Now()
	return projection, nil
}

// verificationTimeout uses a real static guest and Cloud cleanup. The injected
// verification outage/result latency is not a guest or hardware failure.
func (r *cloudRun) verificationTimeout(ctx context.Context, t *testing.T, h *providerControlPlane, cfg *Config, a *cloudGuest) (resultErr error) {
	t.Helper()
	ctx, abort := context.WithTimeout(ctx, 18*time.Minute)
	stage := "verified-baseline"
	evidence := map[string]any{
		"passed": false, "run": r.ledger.Run,
		"fault": "injected provider verification unavailability and delayed verified result delivery",
		"cloud": "real requests and owned instance termination", "attestation": "real TDX verification before delayed result delivery",
	}
	defer func() {
		abort()
		evidence["stage"] = stage
		if resultErr != nil {
			resultErr = fmt.Errorf("verification timeout %s: %w", stage, resultErr)
		}
		resultErr = errors.Join(resultErr, cloudWrite(filepath.Join(r.dir, "verification-timeout.json"), evidence))
	}()
	if a == nil || a.rec == nil || a.rec.InstanceID == "" {
		return errors.New("verification timeout requires an already attested owned guest")
	}
	before := a.rec
	evidence["podUID"], evidence["instanceID"] = before.UID, before.InstanceID
	key := client.ObjectKey{Namespace: before.Namespace, Name: before.Name}
	read := func() (*corev1.Pod, *record, error) {
		pod := &corev1.Pod{}
		if err := h.client.Get(ctx, key, pod); err != nil {
			return nil, nil, err
		}
		if pod.UID != before.UID || pod.Spec.NodeName != cfg.NodeName || !pod.DeletionTimestamp.IsZero() || !slices.Contains(pod.Finalizers, finalizer) {
			return nil, nil, errors.New("verification timeout Pod lost its original scheduling or cleanup authority")
		}
		rec, err := r.snapshot(ctx, h, cfg, "a")
		if err != nil {
			return nil, nil, err
		}
		if rec.Version != 1 || rec.Key != before.Key || rec.InstanceID != before.InstanceID || !reflect.DeepEqual(rec.Request, before.Request) || rec.VerificationTimeoutSeconds != defaultVerificationTimeoutSeconds {
			return nil, nil, errors.New("verification timeout changed the frozen guest or launch intent")
		}
		return pod, rec, nil
	}
	wait := func(budget time.Duration, observe func() (bool, error)) error {
		until, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		for {
			select {
			case <-until.Done():
				return until.Err()
			case <-h.manager.done:
				return errors.New("provider manager stopped during verification acceptance")
			default:
			}
			complete, err := observe()
			if err != nil || complete {
				return err
			}
			if err := cloudPause(until, time.Second); err != nil {
				return err
			}
		}
	}
	var baseline *corev1.Pod
	if err := wait(3*time.Minute, func() (bool, error) {
		pod, rec, err := read()
		if err != nil {
			return false, err
		}
		if rec.TerminalStatus != nil || rec.DeleteRequested || rec.Deleted {
			return false, errors.New("guest became terminal before verification fault injection")
		}
		baseline = pod
		last := map[string]any{"phase": pod.Status.Phase, "reason": truncateBootReason(pod.Status.Reason), "ready": controlPlanePodReady(pod), "hasEndpoints": pod.Annotations[endpointsAnnotation] != ""}
		if rec.VerificationDeadline != nil {
			last["verificationDeadline"] = *rec.VerificationDeadline
		}
		evidence["lastBaseline"] = last
		return rec.VerificationDeadline == nil && controlPlanePodReady(pod) && pod.Annotations[endpointsAnnotation] != "", nil
	}); err != nil {
		return err
	}
	evidence["verifiedProviderBaseline"] = true
	stage = "verification-unavailable"
	stop := func() error {
		h.manager.stop(t)
		select {
		case <-h.manager.done:
			return h.manager.err
		default:
			return errors.New("previous provider manager has not stopped")
		}
	}
	if err := stop(); err != nil {
		return err
	}
	h.cfg = cfg
	faultStarted := time.Now()
	h.startProvider(t, r.api, func(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
		if rec.UID == before.UID {
			return podstatus.PodProjection{}, errors.New("acceptance injected verification unavailability")
		}
		return readGuest(ctx, rec, address)
	}, nil)
	var frozen time.Time
	if err := wait(2*time.Minute, func() (bool, error) {
		pod, rec, err := read()
		if err != nil {
			return false, err
		}
		if rec.TerminalStatus != nil || rec.DeleteRequested || rec.Deleted {
			return false, errors.New("guest became terminal before restart acceptance")
		}
		if rec.VerificationDeadline == nil || pod.Status.Reason != "AttestationUnavailable" || controlPlanePodReady(pod) || pod.Annotations[endpointsAnnotation] != "" {
			return false, nil
		}
		frozen = *rec.VerificationDeadline
		budget := time.Duration(defaultVerificationTimeoutSeconds) * time.Second
		if frozen.Before(faultStarted.Add(budget)) || frozen.After(time.Now().Add(budget)) {
			return false, errors.New("verification outage did not begin a fresh frozen-duration window")
		}
		return true, nil
	}); err != nil {
		return err
	}
	evidence["verificationDeadline"], evidence["verificationTimeoutSeconds"] = frozen, defaultVerificationTimeoutSeconds
	evidence["unavailabilityWithdrawsReadinessAndEndpoints"] = true
	stage = "restart-and-verified-result"
	if err := stop(); err != nil {
		return err
	}
	next := *cfg
	next.VerificationTimeoutSeconds = 3 * defaultVerificationTimeoutSeconds
	h.cfg = &next
	late := &cloudDelayedGuest{
		uid: before.UID, deadline: frozen, deliverAt: frozen.Add(time.Second), abort: ctx,
		captured: make(chan time.Time, 1), delivered: make(chan time.Time, 1),
		read: func(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
			projection, err := readGuest(ctx, rec, address)
			if err == nil {
				var status corev1.PodStatus
				status, err = projectedStatus(rec, projection, baseline, "")
				if err == nil && status.Phase != corev1.PodRunning {
					err = errors.New("late-result acceptance requires a valid running guest projection")
				}
			}
			return projection, err
		},
	}
	h.startProvider(t, r.api, late.readGuest, nil)
	if err := wait(time.Minute, func() (bool, error) {
		select {
		case verifiedAt := <-late.captured:
			evidence["verifiedResultCapturedAt"] = verifiedAt
			_, rec, err := read()
			if err != nil {
				return false, err
			}
			if rec.VerificationDeadline == nil || !rec.VerificationDeadline.Equal(frozen) {
				return false, errors.New("provider restart refreshed the persisted verification deadline")
			}
			evidence["restartPreservedDeadline"] = true
			return true, nil
		default:
			return false, nil
		}
	}); err != nil {
		return err
	}
	stage = "late-result-delivery"
	t.Log("provider restart retained the frozen verification window; delaying a real verified result until expiry")
	select {
	case deliveredAt := <-late.delivered:
		if deliveredAt.Before(frozen) {
			return errors.New("verified result was delivered before the persisted deadline")
		}
		evidence["verifiedResultDeliveredAt"] = deliveredAt
	case <-ctx.Done():
		return ctx.Err()
	case <-h.manager.done:
		return errors.New("provider manager stopped before delayed result delivery")
	}
	stage = "provider-termination"
	if err := wait(3*time.Minute, func() (bool, error) {
		pod, rec, err := read()
		if err != nil {
			return false, err
		}
		if rec.VerificationDeadline == nil || !rec.VerificationDeadline.Equal(frozen) {
			return false, errors.New("late verified result cleared or changed the frozen deadline")
		}
		if controlPlanePodReady(pod) || pod.Annotations[endpointsAnnotation] != "" {
			return false, errors.New("late verified result restored readiness or endpoints")
		}
		if rec.TerminalStatus == nil {
			return false, nil
		}
		if evidence["terminalObservedAt"] == nil {
			evidence["terminalObservedAt"] = time.Now()
		}
		if rec.TerminalStatus.Reason != verificationTimeoutReason {
			return false, errors.New("guest terminated for a reason other than verification timeout")
		}
		if pod.Status.Phase != corev1.PodFailed || pod.Status.Reason != verificationTimeoutReason || !rec.DeleteRequested || !rec.Deleted {
			return false, nil
		}
		in, err := r.getOwned(ctx, "a")
		if err != nil {
			return false, err
		}
		return in != nil && in.ID == before.InstanceID && in.Status == "terminated", nil
	}); err != nil {
		return err
	}
	stage = "complete"
	evidence["passed"], evidence["lateResultRefused"], evidence["providerConfirmedTerminationBeforePodDeletion"] = true, true, true
	evidence["terminationConfirmedAt"] = time.Now()
	t.Log("late verified result was refused; production provider confirmed owned VM termination before Pod deletion")
	return nil
}
