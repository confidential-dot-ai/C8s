package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/confidential-dot-ai/c8s/api/v1alpha2"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// Label stamped on operator-managed headless Services so they can be found
// (and garbage-collected) without guessing names.
const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "c8s-operator"
)

// collisionRequeue is how often the reconciler retries while a foreign
// Service occupies the desired name. The foreign object emits no watch
// events this controller sees (it is unlabeled and un-owned), so without a
// requeue the managed Service would not appear until the workload's next
// spec change or an operator restart.
const collisionRequeue = 5 * time.Minute

// WorkloadServiceReconciler provisions one headless Service per workload whose
// pod template carries the confidential.ai/cw annotation. Headless DNS returns
// pod IPs, so a client dialing the Service name (e.g. router's upstream)
// hits a pod IP directly and the node-level armtls-mesh wraps the connection in
// attested mTLS — the mesh is pod-IP-routed and cannot intercept Service VIPs.
//
// One reconciler instance is registered per workload kind (Deployment,
// StatefulSet, DaemonSet — the kinds ConfidentialWorkload mirrors). The
// Service carries a controller ownerReference to the workload, so workload
// deletion GCs it; annotation removal or rename is handled here.
type WorkloadServiceReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
	Kind     v1alpha2.WorkloadKind

	// Excluded namespaces never get a managed Service. Mirrors the webhook's
	// exclusions: pods there are never injected, so they never carry the cw
	// label the Service selects on.
	Excluded map[string]struct{}
}

// workloadServiceKinds is the single list of kinds that get a managed
// headless Service — the kinds ConfidentialWorkload mirrors. The runner
// registers one reconciler per entry.
var workloadServiceKinds = []v1alpha2.WorkloadKind{
	v1alpha2.WorkloadKindDeployment,
	v1alpha2.WorkloadKindStatefulSet,
	v1alpha2.WorkloadKindDaemonSet,
}

// newWorkload returns the typed object for r.Kind, or nil for kinds the
// reconciler does not support (rejected at SetupWithManager time).
func (r *WorkloadServiceReconciler) newWorkload() client.Object {
	return newWorkloadObject(r.Kind)
}

// newWorkloadObject returns the typed workload object for kind, or nil for a
// kind outside the ConfidentialWorkload-mirrored set.
func newWorkloadObject(kind v1alpha2.WorkloadKind) client.Object {
	switch kind {
	case v1alpha2.WorkloadKindDeployment:
		return &appsv1.Deployment{}
	case v1alpha2.WorkloadKindStatefulSet:
		return &appsv1.StatefulSet{}
	case v1alpha2.WorkloadKindDaemonSet:
		return &appsv1.DaemonSet{}
	}
	return nil
}

// podTemplate returns the workload's pod template, nil for types outside
// newWorkload's set.
func podTemplate(obj client.Object) *corev1.PodTemplateSpec {
	switch w := obj.(type) {
	case *appsv1.Deployment:
		return &w.Spec.Template
	case *appsv1.StatefulSet:
		return &w.Spec.Template
	case *appsv1.DaemonSet:
		return &w.Spec.Template
	}
	return nil
}

func (r *WorkloadServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("workload", req.NamespacedName, "kind", string(r.Kind))

	obj := r.newWorkload()
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		// Workload gone: its Service is GC'd via the controller ownerReference.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	template := podTemplate(obj)

	// The desired Service set is {desiredName}, or empty when the workload
	// has no (nameable) cw id or its namespace is excluded. An excluded
	// namespace still flows through the delete below, so a namespace joining
	// the exclusion list after Services were provisioned gets cleaned up.
	cwID := template.Annotations[webhook.AnnotationWorkload]
	desiredName := ""
	if _, excluded := r.Excluded[req.Namespace]; !excluded {
		desiredName = webhook.WorkloadServiceName(cwID)
		if cwID != "" && desiredName == "" {
			l.Info("cw id does not yield a valid Service name; skipping headless Service",
				"cw", cwID)
		}
	}

	if err := r.deleteStaleServices(ctx, obj, desiredName); err != nil {
		return ctrl.Result{}, err
	}
	if desiredName == "" {
		return ctrl.Result{}, nil
	}

	svc := &corev1.Service{Name: desiredName, Namespace: obj.GetNamespace()}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		if svc.UID != "" && !metav1.IsControlledBy(svc, obj) {
			return errServiceNotManaged
		}
		if svc.Labels == nil {
			svc.Labels = map[string]string{}
		}
		svc.Labels[managedByLabel] = managedByValue
		if err := controllerutil.SetControllerReference(obj, svc, r.Scheme); err != nil {
			return err
		}
		svc.Spec.ClusterIP = corev1.ClusterIPNone
		svc.Spec.Selector = map[string]string{webhook.LabelWorkload: cwID}
		svc.Spec.Ports = servicePorts(template)
		return nil
	})
	if errors.Is(err, errServiceNotManaged) || apierrors.IsAlreadyExists(err) {
		// A Service with the desired name exists but belongs to someone else
		// (a user object, or another workload claiming the same cw id). Leave
		// it alone rather than fight over it. AlreadyExists is the same case
		// seen through the label-scoped cache: a foreign Service is invisible
		// to the cache, so CreateOrUpdate tries Create and the API refuses.
		l.Info("a Service with this name exists and is not controlled by this workload; not adopting",
			"service", desiredName)
		r.Recorder.Eventf(obj, nil, corev1.EventTypeWarning, "ServiceNameConflict", "ProvisionService",
			"Service %s exists and is not controlled by this workload; the c8s headless Service will not be created until it is removed", desiredName)
		return ctrl.Result{RequeueAfter: collisionRequeue}, nil
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure headless Service %s/%s: %w", obj.GetNamespace(), desiredName, err)
	}
	if op != controllerutil.OperationResultNone {
		l.Info("headless Service reconciled", "service", desiredName, "op", string(op))
	}
	return ctrl.Result{}, nil
}

var errServiceNotManaged = errors.New("existing Service is not controlled by this workload")

// deleteStaleServices removes managed Services controlled by this workload
// whose name no longer matches the desired one — the cw annotation was
// removed or renamed. Workload deletion needs no handling here (ownerRef GC).
func (r *WorkloadServiceReconciler) deleteStaleServices(ctx context.Context, obj client.Object, desiredName string) error {
	l := log.FromContext(ctx)
	var svcs corev1.ServiceList
	if err := r.List(ctx, &svcs,
		client.InNamespace(obj.GetNamespace()),
		client.MatchingLabels{managedByLabel: managedByValue}); err != nil {
		return fmt.Errorf("list managed Services: %w", err)
	}
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if svc.Name == desiredName || !metav1.IsControlledBy(svc, obj) {
			continue
		}
		if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stale Service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
		l.Info("deleted stale managed Service", "service", svc.Name, "namespace", svc.Namespace)
	}
	return nil
}

// servicePorts mirrors the pod template's containerPorts (regular and init
// containers — native sidecars declare ports on init containers) onto Service
// ports, deduplicated by port/protocol. Names are always generated from that
// key, so they are unique by construction. An empty result is fine: headless
// Services may omit ports, and DNS still returns the pod IPs.
func servicePorts(template *corev1.PodTemplateSpec) []corev1.ServicePort {
	type portKey struct {
		port     int32
		protocol corev1.Protocol
	}
	seen := make(map[portKey]struct{})
	var out []corev1.ServicePort

	for _, containers := range [][]corev1.Container{template.Spec.InitContainers, template.Spec.Containers} {
		for i := range containers {
			for _, cp := range containers[i].Ports {
				protocol := cp.Protocol
				if protocol == "" {
					protocol = corev1.ProtocolTCP
				}
				key := portKey{port: cp.ContainerPort, protocol: protocol}
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, corev1.ServicePort{
					Name:     servicePortName(cp.ContainerPort, protocol),
					Port:     cp.ContainerPort,
					Protocol: protocol,
				})
			}
		}
	}
	return out
}

func servicePortName(port int32, protocol corev1.Protocol) string {
	if protocol != corev1.ProtocolTCP {
		return fmt.Sprintf("port-%d-%s", port, strings.ToLower(string(protocol)))
	}
	return fmt.Sprintf("port-%d", port)
}

func (r *WorkloadServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	obj := r.newWorkload()
	if obj == nil {
		return fmt.Errorf("unsupported workload kind %q", r.Kind)
	}
	// GenerationChangedPredicate: the reconciler only reads spec (template
	// annotations and ports), and spec changes bump metadata.generation, so
	// status-only churn (rollout progress, replica counts) is filtered out.
	return ctrl.NewControllerManagedBy(mgr).
		For(obj, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.Service{}).
		Named("workload-service-" + strings.ToLower(string(r.Kind))).
		Complete(r)
}
