package podprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

const (
	pollInterval = 10 * time.Second
	// optInRequiredReason fails a pod bound to the node without the opt-in.
	optInRequiredReason = "PodCVMOptInRequired"
	// instanceDestroyedReason fails a deleted pod whose instance the provider
	// destroyed before it reported a terminal phase of its own.
	instanceDestroyedReason = "InstanceDestroyed"
)

// Reconciler owns a single provider's immutable Pod-to-instance records.
// One leader and one mutex serialize normal and orphan paths around side effects.
type Reconciler struct {
	client     client.Client
	cfg        *Config
	cloud      cloudAPI
	guest      guestReader
	assignment assignmentVerifier
	now        func() time.Time
	ownsNode   func(context.Context) error
	recorder   events.EventRecorder
	mu         sync.Mutex
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, req.NamespacedName, pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if pod.Spec.NodeName != r.cfg.NodeName {
		return ctrl.Result{}, nil
	}
	// Deletion comes first: a pod whose opt-in was removed past admission
	// still owns an instance, and only deletePod destroys it and releases
	// the finalizer.
	if !pod.DeletionTimestamp.IsZero() {
		return r.deletePod(ctx, pod)
	}
	if pod.UID == "" {
		return ctrl.Result{}, errors.New("scheduled Pod has no UID")
	}
	rec, secret, err := r.loadRecord(ctx, identityKey(r.cfg.ProviderID, string(pod.UID)))
	if err != nil && !apierrors.IsNotFound(err) {
		return r.unavailable(ctx, pod, "ProviderStateUnavailable", err)
	}
	optedIn := pod.Annotations[Annotation] == "true"
	if !optedIn && rec == nil {
		if pod.Status.Phase == corev1.PodFailed && pod.Status.Reason == optInRequiredReason {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.publishStatus(ctx, pod, failedStatus(pod, optInRequiredReason, r.now()))
	}
	if rec != nil {
		// Existing cleanup authority does not depend on a healthy virtual node.
		if rec.TerminalStatus != nil || rec.DeleteRequested || rec.Deleted {
			return r.finish(ctx, pod, rec, secret)
		}
		// A launched pod whose opt-in was removed past admission still owns an
		// instance: stop it rather than leave it running unverified.
		if !optedIn {
			return r.stop(ctx, pod, rec, secret, optInRequiredReason)
		}
		if r.verificationExpired(rec) {
			return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
		}
	}
	if r.ownsNode != nil {
		callCtx, cancel := r.verificationContext(ctx, rec)
		err := r.ownsNode(callCtx)
		cancel()
		if err != nil {
			return r.unverified(ctx, pod, rec, secret, "ProviderNodeUnavailable", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return ctrl.Result{}, err
	}
	if !controllerutil.ContainsFinalizer(pod, finalizer) {
		before := pod.DeepCopy()
		controllerutil.AddFinalizer(pod, finalizer)
		if err := r.client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, err
		}
	}
	if rec == nil {
		rec, secret, err = r.ensureRecord(ctx, pod)
		if err != nil {
			return r.unavailable(ctx, pod, "LaunchRefused", err)
		}
	}
	if rec.TerminalStatus != nil || rec.DeleteRequested || rec.Deleted {
		return r.finish(ctx, pod, rec, secret)
	}
	if err := ctx.Err(); err != nil {
		return ctrl.Result{}, err
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	if err := matchesPod(rec, pod); err != nil {
		return r.unverified(ctx, pod, rec, secret, "FrozenPodChanged", err)
	}
	callCtx, cancel := r.verificationContext(ctx, rec)
	defer cancel()
	in, err := ensureCloudInstance(callCtx, r.cloud, &rec.instanceIntent, func() error { return r.save(callCtx, rec, secret) })
	if ctx.Err() != nil {
		return ctrl.Result{}, ctx.Err()
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	if err != nil {
		return r.unverified(ctx, pod, rec, secret, "CloudUnavailable", err)
	}
	if in == nil {
		return r.stop(ctx, pod, rec, secret, "InstanceGone")
	}
	if err := validateInstance(&rec.instanceIntent, in); err != nil {
		return r.stop(ctx, pod, rec, secret, "InstanceIdentityMismatch")
	}
	if in.Boot.Count > 1 {
		return r.stop(ctx, pod, rec, secret, "GuestRebooted")
	}
	switch in.Status {
	case "failed", "terminated", "terminating", "stopped":
		return r.stop(ctx, pod, rec, secret, "InstanceEnded")
	case "running":
	default:
		return r.unverified(ctx, pod, rec, secret, "InstanceStarting", nil)
	}
	return r.running(ctx, callCtx, pod, rec, secret, in)
}

func matchesPod(rec *record, pod *corev1.Pod) error {
	if rec.UID != pod.UID || rec.Namespace != pod.Namespace || rec.Name != pod.Name {
		return errors.New("provider record belongs to another Pod")
	}
	frozen, err := launchconfig.ParsePodManifest(rec.Pod)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(frozen.Spec, guestPod(pod).Spec) {
		return errors.New("scheduled Pod specification differs from its immutable launch")
	}
	return nil
}

// running reads the pod's status from a running instance over a verified
// connection. A guest that reports no verifiable pod yet is assigned the pod.
func (r *Reconciler) running(ctx, callCtx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret, in *instance) (ctrl.Result, error) {
	address, apps, podIP, err := endpoints(rec.Request.Network, in)
	if err != nil {
		return r.unverified(ctx, pod, rec, secret, "EndpointsPending", err)
	}
	projection, err := r.guest(callCtx, rec, address)
	if ctx.Err() != nil {
		return ctrl.Result{}, ctx.Err()
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	reason := "AttestationUnavailable"
	var status corev1.PodStatus
	if err == nil {
		reason = "GuestStatusRefused"
		status, err = projectedStatus(rec, projection, pod, podIP, rec.Key)
	}
	if err != nil {
		// No verified pod status: the guest waits for the assignment, or a
		// sent assignment is replayed, which tells a guest holding the pod from
		// one holding another. An accepted assignment is pending until the
		// guest reports the pod; a refused one keeps the status failure's reason.
		if assignErr := r.assign(callCtx, rec, secret, address); assignErr != nil {
			err = errors.Join(err, assignErr)
		} else {
			reason, err = "AssignmentPending", nil
		}
		if ctx.Err() != nil {
			return ctrl.Result{}, ctx.Err()
		}
		if r.verificationExpired(rec) {
			return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
		}
		return r.unverified(ctx, pod, rec, secret, reason, err)
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	if len(rec.Assignment) == 0 {
		return r.stop(ctx, pod, rec, secret, "UnexpectedAssignedGuest")
	}
	if status.Phase == corev1.PodSucceeded || status.Phase == corev1.PodFailed {
		rec.TerminalStatus = &status
		if err := r.save(ctx, rec, secret); err != nil {
			return ctrl.Result{}, err
		}
		return r.finish(ctx, pod, rec, secret)
	}
	if rec.VerificationDeadline != nil {
		rec.VerificationDeadline = nil
		if err := r.save(ctx, rec, secret); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.publishEndpoints(ctx, pod, apps); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: pollInterval}, r.publishStatus(ctx, pod, status)
}

func (r *Reconciler) unavailable(ctx context.Context, pod *corev1.Pod, reason string, cause error) (ctrl.Result, error) {
	if err := r.publishEndpoints(ctx, pod, nil); err != nil {
		return ctrl.Result{}, errors.Join(cause, err)
	}
	err := r.publishStatus(ctx, pod, unknownStatus(pod, reason, r.now()))
	return ctrl.Result{RequeueAfter: pollInterval}, errors.Join(cause, err)
}

func (r *Reconciler) stop(ctx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret, reason string) (ctrl.Result, error) {
	if err := ctx.Err(); err != nil {
		return ctrl.Result{}, err
	}
	status := failedStatus(pod, reason, r.now())
	rec.TerminalStatus = &status
	if err := r.save(ctx, rec, secret); err != nil {
		return ctrl.Result{}, err
	}
	return r.finish(ctx, pod, rec, secret)
}

func (r *Reconciler) finish(ctx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret) (ctrl.Result, error) {
	var publicationErr error
	if rec.TerminalStatus != nil {
		publicationErr = r.publishStatus(ctx, pod, *rec.TerminalStatus)
	}
	publicationErr = errors.Join(publicationErr, r.publishEndpoints(ctx, pod, nil))
	// The durable terminal decision still requires cleanup when Kubernetes
	// rejects a status/annotation patch. Keep retrying both independently.
	done, err := r.removeInstance(ctx, rec, secret)
	if err != nil || !done {
		return ctrl.Result{RequeueAfter: pollInterval}, errors.Join(publicationErr, err)
	}
	return ctrl.Result{}, publicationErr
}

func (r *Reconciler) deletePod(ctx context.Context, pod *corev1.Pod) (ctrl.Result, error) {
	key := identityKey(r.cfg.ProviderID, string(pod.UID))
	rec, secret, err := r.loadRecord(ctx, key)
	if apierrors.IsNotFound(err) {
		return ctrl.Result{}, r.finishDeletion(ctx, pod, nil)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	done, err := r.removeInstance(ctx, rec, secret)
	if err != nil || !done {
		return ctrl.Result{RequeueAfter: pollInterval}, err
	}
	// Finish the Pod before deleting the record. A crash between them
	// leaves an orphan record the sweep can safely collect.
	if err := r.finishDeletion(ctx, pod, rec); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.discard(ctx, secret)
}

// terminalStatus is the phase a deleted pod leaves with: the terminal status
// its record holds, its own terminal phase, or Failed, so that a controller
// waiting for the pod to end sees it end.
func terminalStatus(pod *corev1.Pod, rec *record, now time.Time) corev1.PodStatus {
	if rec != nil && rec.TerminalStatus != nil {
		return *rec.TerminalStatus
	}
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return pod.Status
	}
	return failedStatus(pod, instanceDestroyedReason, now)
}

// finishDeletion does the kubelet's part once the Pod's instance is gone: it
// publishes the terminal phase, releases the finalizer and removes the Pod
// object with a zero grace period. No kubelet runs for the virtual node, so
// nothing else ends a terminating Pod bound to it.
func (r *Reconciler) finishDeletion(ctx context.Context, pod *corev1.Pod, rec *record) error {
	if err := r.releaseFinalizer(ctx, pod, rec); err != nil {
		return err
	}
	uid := pod.UID
	return client.IgnoreNotFound(r.client.Delete(ctx, pod, client.GracePeriodSeconds(0), client.Preconditions{UID: &uid}))
}

func (r *Reconciler) releaseFinalizer(ctx context.Context, pod *corev1.Pod, rec *record) error {
	if !controllerutil.ContainsFinalizer(pod, finalizer) {
		return nil
	}
	if err := client.IgnoreNotFound(r.publishStatus(ctx, pod, terminalStatus(pod, rec, r.now()))); err != nil {
		return err
	}
	before := pod.DeepCopy()
	controllerutil.RemoveFinalizer(pod, finalizer)
	return client.IgnoreNotFound(r.client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})))
}

// removeInstance destroys the instance a record owns and reports whether
// destruction is confirmed.
func (r *Reconciler) removeInstance(ctx context.Context, rec *record, secret *corev1.Secret) (bool, error) {
	return removeCloudInstance(ctx, r.cloud, &rec.instanceIntent, func() error { return r.save(ctx, rec, secret) })
}

func (r *Reconciler) publishStatus(ctx context.Context, pod *corev1.Pod, status corev1.PodStatus) error {
	if reflect.DeepEqual(pod.Status, status) {
		return nil
	}
	before := pod.DeepCopy()
	pod.Status = status
	if err := r.client.Status().Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return err
	}
	r.recordTransition(pod, before.Status.Reason)
	return nil
}

// progressReasons are the published reasons of a launch that is still
// advancing. Every other reason reports a refusal, an outage or an ending.
var progressReasons = map[string]bool{
	"InstanceStarting":  true,
	"EndpointsPending":  true,
	"AllocationPending": true,
	"AssignmentPending": true,
}

// recordTransition records one Event when the published status changes
// reason, so polls of an unchanged state stay silent.
func (r *Reconciler) recordTransition(pod *corev1.Pod, previous string) {
	reason := pod.Status.Reason
	if r.recorder == nil || reason == previous {
		return
	}
	switch {
	case reason == "":
		// Verified guest status replaced a waiting or outage reason, whatever
		// phase the guest reports (often Pending while containers start).
		r.recorder.Eventf(pod, nil, corev1.EventTypeNormal, "PodCVMVerified", "PublishStatus", "The Pod CVM reports verified status")
	case progressReasons[reason] || pod.Status.Phase == corev1.PodSucceeded:
		r.recorder.Eventf(pod, nil, corev1.EventTypeNormal, reason, "PublishStatus", "%s", pod.Status.Message)
	default:
		r.recorder.Eventf(pod, nil, corev1.EventTypeWarning, reason, "PublishStatus", "%s", pod.Status.Message)
	}
}

func (r *Reconciler) publishEndpoints(ctx context.Context, pod *corev1.Pod, apps []endpoint) error {
	value := ""
	if len(apps) != 0 {
		slices.SortFunc(apps, func(a, b endpoint) int {
			if a.Name < b.Name {
				return -1
			}
			if a.Name > b.Name {
				return 1
			}
			return 0
		})
		var err error
		value, err = endpointJSON(apps)
		if err != nil {
			return err
		}
	}
	if pod.Annotations[endpointsAnnotation] == value {
		return nil
	}
	before := pod.DeepCopy()
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	if value == "" {
		delete(pod.Annotations, endpointsAnnotation)
	} else {
		pod.Annotations[endpointsAnnotation] = value
	}
	return r.client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
}

func (r *Reconciler) sweep(ctx context.Context) error {
	var records corev1.SecretList
	if err := r.client.List(ctx, &records, client.InNamespace(r.cfg.Namespace), client.MatchingLabels{ownerLabel: r.cfg.ProviderID}); err != nil {
		return err
	}
	var errs []error
	for _, s := range records.Items {
		if err := r.sweepRecord(ctx, s.Name); err != nil {
			errs = append(errs, fmt.Errorf("reconcile provider record %s: %w", s.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (r *Reconciler) sweepRecord(ctx context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, secret, err := r.loadRecord(ctx, key)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	pod := &corev1.Pod{}
	err = r.client.Get(ctx, types.NamespacedName{Namespace: rec.Namespace, Name: rec.Name}, pod)
	if err == nil && pod.UID == rec.UID {
		return nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	done, err := r.removeInstance(ctx, rec, secret)
	if err != nil || !done {
		return err
	}
	return r.discard(ctx, secret)
}
