package podprovider

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	defaultVerificationTimeoutSeconds = 600
	verificationTimeoutReason         = "GuestVerificationTimedOut"
	// podIdentityEndedReason names a failed phase the guest reports with no
	// container terminated: the admission plugin ended the pod identity, so the
	// status service failed a pod the kubelet alone would keep recreating.
	podIdentityEndedReason = "PodIdentityEnded"
)

func validVerificationTimeout(seconds int64) bool {
	return seconds >= 30 && seconds <= 86400
}

func (r *Reconciler) beginVerification(rec *record) {
	deadline := r.now().Add(time.Duration(rec.VerificationTimeoutSeconds) * time.Second)
	rec.VerificationDeadline = &deadline
}

func (r *Reconciler) verificationExpired(rec *record) bool {
	return rec.VerificationDeadline != nil && !r.now().Before(*rec.VerificationDeadline)
}

// Use a child context for network work: the parent remains available to
// persist failure and cleanup intent after the verification budget expires.
func (r *Reconciler) verificationContext(ctx context.Context, rec *record) (context.Context, context.CancelFunc) {
	if rec == nil || rec.VerificationDeadline == nil {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, rec.VerificationDeadline.Sub(r.now()))
}

func (r *Reconciler) unverified(ctx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret, reason string, cause error) (ctrl.Result, error) {
	if err := ctx.Err(); err != nil {
		return ctrl.Result{}, err
	}
	if rec == nil {
		return r.unavailable(ctx, pod, reason, cause)
	}
	if rec.VerificationDeadline == nil {
		r.beginVerification(rec)
		if err := r.save(ctx, rec, secret); err != nil {
			return r.unavailable(ctx, pod, reason, err)
		}
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	// Expected unavailability uses the deadline's schedule, not the controller's
	// increasing error backoff. Status exposes only the fixed reason code.
	result, err := r.unavailable(ctx, pod, reason, nil)
	result.RequeueAfter = min(pollInterval, rec.VerificationDeadline.Sub(r.now()))
	if result.RequeueAfter <= 0 && err == nil {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	return result, err
}
