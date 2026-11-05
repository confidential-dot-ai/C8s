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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

const pollInterval = 10 * time.Second

// Reconciler owns a single provider's immutable Pod-to-instance assignments.
// One leader and one mutex serialize normal and orphan paths around side effects.
type Reconciler struct {
	client     client.Client
	cfg        *Config
	cloud      cloudAPI
	guest      guestReader
	assignment assignmentVerifier
	now        func() time.Time
	ownsNode   func(context.Context) error
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
	if pod.Annotations[Annotation] != "true" {
		if pod.Status.Phase == corev1.PodFailed && pod.Status.Reason == "PodCVMOptInRequired" {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.publishStatus(ctx, pod, failedStatus(pod, "PodCVMOptInRequired", r.now()))
	}
	if pod.UID == "" {
		return ctrl.Result{}, errors.New("scheduled Pod has no UID")
	}
	rec, secret, err := r.loadRecord(ctx, identityKey(r.cfg.ProviderID, string(pod.UID)))
	if err != nil && !apierrors.IsNotFound(err) {
		return r.unavailable(ctx, pod, "LaunchRefused", err)
	}
	if rec != nil {
		// Existing cleanup authority does not depend on a healthy virtual node.
		if rec.TerminalStatus != nil || rec.DeleteRequested || rec.Deleted {
			return r.finish(ctx, pod, rec, secret)
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
	// A direct launch owns its instance; a pooled Pod resolves the slot it
	// claimed. From here both modes share one instance and status path.
	var p *poolRecord
	var slot *corev1.Secret
	intent := &rec.instanceIntent
	callCtx, cancel := r.verificationContext(ctx, rec)
	defer cancel()
	save := func() error { return r.save(callCtx, rec, secret) }
	if rec.Version == 2 {
		p, slot, err = r.selectPool(ctx, rec, secret)
		if err != nil {
			return r.unverified(ctx, pod, rec, secret, "AllocationPending", err)
		}
		if p.DeleteRequested || p.Deleted {
			return r.stop(ctx, pod, rec, secret, "InstanceEnded")
		}
		intent = &p.instanceIntent
		save = func() error { return r.savePool(callCtx, p, slot) }
	}
	in, err := ensureCloudInstance(callCtx, r.cloud, intent, r.now(), save)
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
	if err := validateInstance(intent, in); err != nil {
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
	if p != nil {
		// A generic boot was created with the status port only; the pod's
		// application ports are opened after the claim.
		ready, err := r.poolIngress(callCtx, rec, p, in)
		if ctx.Err() != nil {
			return ctrl.Result{}, ctx.Err()
		}
		if r.verificationExpired(rec) {
			return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
		}
		if err != nil || !ready {
			return r.unverified(ctx, pod, rec, secret, "EndpointsPending", err)
		}
	}
	return r.running(ctx, callCtx, pod, rec, secret, intent, in, p, slot)
}

func matchesPod(rec *record, pod *corev1.Pod) error {
	if rec.UID != pod.UID || rec.Namespace != pod.Namespace || rec.Name != pod.Name {
		return errors.New("provider record belongs to another Pod")
	}
	doc, err := rec.document()
	if err != nil {
		return err
	}
	frozen, err := launchconfig.ParsePodManifest([]byte(doc.Pod.Manifest))
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(frozen.Spec, guestPod(pod).Spec) {
		return errors.New("scheduled Pod specification differs from its immutable launch")
	}
	return nil
}

// running reads the pod's status from a running instance over a verified
// connection. A pooled guest that reports no verifiable pod yet is assigned.
func (r *Reconciler) running(ctx, callCtx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret, intent *instanceIntent, in *instance, p *poolRecord, slot *corev1.Secret) (ctrl.Result, error) {
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
		status, err = projectedStatus(rec, projection, pod, podIP, intent.Key)
	}
	if err != nil {
		if p == nil {
			return r.unverified(ctx, pod, rec, secret, reason, err)
		}
		err = r.assignPool(callCtx, rec, p, slot, address)
		if ctx.Err() != nil {
			return ctrl.Result{}, ctx.Err()
		}
		if r.verificationExpired(rec) {
			return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
		}
		return r.unverified(ctx, pod, rec, secret, "AssignmentPending", err)
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, secret, verificationTimeoutReason)
	}
	if p != nil && len(p.Assignment) == 0 {
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
		return ctrl.Result{}, r.releaseFinalizer(ctx, pod)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	done, err := r.removeInstance(ctx, rec, secret)
	if err != nil || !done {
		return ctrl.Result{RequeueAfter: pollInterval}, err
	}
	// Remove the finalizer before deleting the record. A crash between them
	// leaves an orphan record the sweep can safely collect.
	if err := r.releaseFinalizer(ctx, pod); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.discard(ctx, secret)
}

func (r *Reconciler) releaseFinalizer(ctx context.Context, pod *corev1.Pod) error {
	if !controllerutil.ContainsFinalizer(pod, finalizer) {
		return nil
	}
	before := pod.DeepCopy()
	controllerutil.RemoveFinalizer(pod, finalizer)
	return client.IgnoreNotFound(r.client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})))
}

// removeInstance destroys the instance a record owns, directly or through the
// slot a pooled Pod claimed, and reports whether destruction is confirmed.
func (r *Reconciler) removeInstance(ctx context.Context, rec *record, secret *corev1.Secret) (bool, error) {
	if rec.Version == 2 {
		return r.removePooledInstance(ctx, rec, secret)
	}
	return removeCloudInstance(ctx, r.cloud, &rec.instanceIntent, r.now(), func() error { return r.save(ctx, rec, secret) })
}

func (r *Reconciler) publishStatus(ctx context.Context, pod *corev1.Pod, status corev1.PodStatus) error {
	if reflect.DeepEqual(pod.Status, status) {
		return nil
	}
	before := pod.DeepCopy()
	pod.Status = status
	return r.client.Status().Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
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
		if s.Labels[slotLabel] == "true" {
			continue
		}
		if err := r.sweepRecord(ctx, s.Name); err != nil {
			errs = append(errs, fmt.Errorf("reconcile provider record %s: %w", s.Name, err))
		}
	}
	r.mu.Lock()
	poolErr := r.maintainPools(ctx)
	r.mu.Unlock()
	return errors.Join(append(errs, poolErr)...)
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
