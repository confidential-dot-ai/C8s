package podprovider

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	defaultVerificationTimeoutSeconds = 600
	verificationTimeoutReason         = "GuestVerificationTimedOut"
	rateLimitedReason                 = "RateLimited"
	// maxRateLimitBackoff caps a Retry-After wait; maxRateLimitJitter caps
	// the random spread added so throttled pods do not retry in step.
	maxRateLimitBackoff = 5 * time.Minute
	maxRateLimitJitter  = 5 * time.Second
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

// outageReason names a failure of the provider's own dependencies rather than
// of the guest. A verified pod keeps its last status through one; only the
// guest's failures start a deadline that ends the pod.
func outageReason(reason string) bool {
	return reason == "CloudUnavailable" || reason == rateLimitedReason || reason == "ProviderNodeUnavailable"
}

// rateLimited publishes RateLimited and waits as Cloud asked (pollInterval
// when it named no wait), plus capped jitter. The wait never runs past the
// verification deadline: throttling does not buy a guest more time.
func (r *Reconciler) rateLimited(ctx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret, hint time.Duration, cause error) (ctrl.Result, error) {
	log.FromContext(ctx).Info("cloud is rate limiting the provider", "pod", client.ObjectKeyFromObject(pod), "retryAfter", hint, "error", cause)
	result, err := r.unverified(ctx, pod, rec, secret, rateLimitedReason, nil)
	if err != nil || result.RequeueAfter <= 0 || (rec != nil && rec.TerminalStatus != nil) {
		return result, err
	}
	wait := min(hint, maxRateLimitBackoff)
	if wait <= 0 {
		wait = pollInterval
	}
	if r.jitter != nil {
		wait += r.jitter(min(wait/4, maxRateLimitJitter))
	}
	if rec != nil && rec.VerificationDeadline != nil {
		wait = min(wait, rec.VerificationDeadline.Sub(r.now()))
	}
	result.RequeueAfter = wait
	return result, nil
}

func (r *Reconciler) unverified(ctx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret, reason string, cause error) (ctrl.Result, error) {
	if err := ctx.Err(); err != nil {
		return ctrl.Result{}, err
	}
	if rec == nil || (rec.VerificationDeadline == nil && outageReason(reason)) {
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
	// increasing error backoff. Status exposes only the fixed reason code; the
	// cause goes to the log.
	if cause != nil {
		log.FromContext(ctx).Info("Pod CVM not verified yet", "reason", reason, "cause", cause.Error())
	}
	result, err := r.unavailable(ctx, pod, reason, nil)
	result.RequeueAfter = min(pollInterval, rec.VerificationDeadline.Sub(r.now()))
	if result.RequeueAfter <= 0 && err == nil {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	return result, err
}
