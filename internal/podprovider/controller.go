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
	client   client.Client
	cfg      *Config
	cloud    cloudAPI
	guest    guestReader
	now      func() time.Time
	ownsNode func(context.Context) error
	mu       sync.Mutex
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
	if pod.Annotations[Annotation] != "true" {
		if pod.Status.Phase == corev1.PodFailed && pod.Status.Reason == "PodCVMOptInRequired" {
			return ctrl.Result{}, nil
		}
		status := failedStatus(pod, "PodCVMOptInRequired", r.now())
		status.Message = "Pods bound to this node must opt into Pod CVM execution"
		return ctrl.Result{}, r.publishStatus(ctx, pod, status)
	}
	if !pod.DeletionTimestamp.IsZero() {
		return r.deletePod(ctx, pod)
	}
	if r.ownsNode != nil {
		if err := r.ownsNode(ctx); err != nil {
			return r.unavailable(ctx, pod, "ProviderNodeUnavailable", err)
		}
	}
	if pod.UID == "" {
		return ctrl.Result{}, errors.New("scheduled Pod has no UID")
	}
	if !controllerutil.ContainsFinalizer(pod, finalizer) {
		before := pod.DeepCopy()
		controllerutil.AddFinalizer(pod, finalizer)
		if err := r.client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, err
		}
	}
	rec, secret, err := r.ensureRecord(ctx, pod)
	if err != nil {
		return r.unavailable(ctx, pod, "LaunchRefused", err)
	}
	if rec.TerminalStatus != nil || rec.DeleteRequested || rec.Deleted {
		return r.finish(ctx, pod, rec, secret)
	}
	if err := matchesPod(rec, pod); err != nil {
		return r.unavailable(ctx, pod, "FrozenPodChanged", err)
	}
	in, err := r.ensureInstance(ctx, rec, secret)
	if err != nil {
		return r.unavailable(ctx, pod, "CloudUnavailable", err)
	}
	if in == nil {
		return r.stop(ctx, pod, rec, secret, "InstanceGone")
	}
	if err := validateInstance(rec, in); err != nil {
		return r.stop(ctx, pod, rec, secret, "InstanceIdentityMismatch")
	}
	if in.Boot.Count > 1 {
		return r.stop(ctx, pod, rec, secret, "GuestRebooted")
	}
	switch in.Status {
	case "failed", "terminated", "terminating", "stopped":
		return r.stop(ctx, pod, rec, secret, "InstanceEnded")
	case "running":
		return r.running(ctx, pod, rec, secret, in)
	default:
		return r.unavailable(ctx, pod, "InstanceStarting", nil)
	}
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

func (r *Reconciler) ensureInstance(ctx context.Context, rec *record, secret *corev1.Secret) (*instance, error) {
	if rec.InstanceID != "" {
		in, err := r.cloud.Get(ctx, rec.InstanceID)
		if errors.Is(err, errCloudNotFound) {
			return nil, nil
		}
		return in, err
	}
	in, err := r.cloud.Find(ctx, rec.Key)
	if err != nil {
		return nil, err
	}
	if in == nil {
		// Cloud retains completed idempotency records for the instance lifetime
		// plus 90 days. Never turn a much older uncertain intent into a new VM.
		if r.now().Sub(rec.CreatedAt) > 24*time.Hour {
			return nil, nil
		}
		if !rec.CreateAttempted {
			rec.CreateAttempted = true
			if err := r.save(ctx, rec, secret); err != nil {
				return nil, err
			}
		}
		in, err = r.cloud.Create(ctx, rec.Key, rec.Request)
		if err != nil {
			return nil, err
		}
	}
	if in == nil || in.ID == "" {
		return nil, errors.New("cloud returned no instance identity")
	}
	for key, value := range rec.Request.Labels {
		if in.Labels[key] != value {
			return nil, errors.New("idempotency result has another owner")
		}
	}
	rec.InstanceID = in.ID
	if err := r.save(ctx, rec, secret); err != nil {
		return nil, err
	}
	return in, nil
}

func (r *Reconciler) running(ctx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret, in *instance) (ctrl.Result, error) {
	address, apps, podIP, err := endpoints(rec, in)
	if err != nil {
		return r.unavailable(ctx, pod, "EndpointsPending", nil)
	}
	projection, err := r.guest(ctx, rec, address)
	if err != nil {
		return r.unavailable(ctx, pod, "AttestationUnavailable", err)
	}
	status, err := projectedStatus(rec, projection, pod, podIP)
	if err != nil {
		return r.unavailable(ctx, pod, "GuestStatusRefused", err)
	}
	if status.Phase == corev1.PodSucceeded || status.Phase == corev1.PodFailed {
		rec.TerminalStatus = &status
		if err := r.save(ctx, rec, secret); err != nil {
			return ctrl.Result{}, err
		}
		return r.finish(ctx, pod, rec, secret)
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
	status := failedStatus(pod, reason, r.now())
	rec.TerminalStatus = &status
	if err := r.save(ctx, rec, secret); err != nil {
		return ctrl.Result{}, err
	}
	return r.finish(ctx, pod, rec, secret)
}

func (r *Reconciler) finish(ctx context.Context, pod *corev1.Pod, rec *record, secret *corev1.Secret) (ctrl.Result, error) {
	if rec.TerminalStatus != nil {
		if err := r.publishStatus(ctx, pod, *rec.TerminalStatus); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.publishEndpoints(ctx, pod, nil); err != nil {
		return ctrl.Result{}, err
	}
	done, err := r.removeInstance(ctx, rec, secret)
	if err != nil || !done {
		return ctrl.Result{RequeueAfter: pollInterval}, err
	}
	return ctrl.Result{}, nil
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

func (r *Reconciler) removeInstance(ctx context.Context, rec *record, secret *corev1.Secret) (bool, error) {
	if rec.Deleted {
		return true, nil
	}
	if !rec.DeleteRequested {
		rec.DeleteRequested = true
		if err := r.save(ctx, rec, secret); err != nil {
			return false, err
		}
	}
	var in *instance
	var err error
	if rec.InstanceID == "" {
		in, err = r.cloud.Find(ctx, rec.Key)
	} else {
		in, err = r.cloud.Get(ctx, rec.InstanceID)
	}
	if errors.Is(err, errCloudNotFound) {
		in, err = nil, nil
	}
	if err != nil {
		return false, err
	}
	if in == nil && rec.InstanceID == "" && rec.CreateAttempted {
		// An empty lookup cannot disprove an in-flight POST. Replay the exact
		// persisted request/key to resolve that intent before releasing cleanup.
		if r.now().Sub(rec.CreatedAt) > 24*time.Hour {
			return false, errors.New("old uncertain create retained for authoritative Cloud resolution")
		}
		in, err = r.cloud.Create(ctx, rec.Key, rec.Request)
		if err != nil {
			return false, err
		}
		if in == nil {
			return false, errors.New("create replay returned no instance")
		}
	}
	if in == nil || in.Status == "terminated" {
		rec.Deleted = true
		return true, r.save(ctx, rec, secret)
	}
	if rec.InstanceID == "" {
		for k, v := range rec.Request.Labels {
			if in.Labels[k] != v {
				return false, errors.New("refusing deletion of a foreign instance")
			}
		}
		rec.InstanceID = in.ID
		if err := r.save(ctx, rec, secret); err != nil {
			return false, err
		}
	}
	if in.ID != rec.InstanceID {
		return false, errors.New("cloud get returned another instance during deletion")
	}
	if err := r.cloud.Delete(ctx, rec.InstanceID); err != nil {
		return false, err
	}
	return false, nil
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
