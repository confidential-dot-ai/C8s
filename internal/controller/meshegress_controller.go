package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// meshEgressCompanionLabel marks a companion policy. Its presence is what
// stops a companion from being treated as a source of its own. The source
// is recoverable from the companion's controller ownerReference.
const meshEgressCompanionLabel = "c8s.confidential.ai/mesh-egress-companion"

// meshEgressCompanionSuffix is appended to the source policy's name.
const meshEgressCompanionSuffix = "-mesh-egress"

const meshEgressControllerName = "mesh-egress-policy"

// MeshEgressReconciler keeps a companion NetworkPolicy beside every
// NetworkPolicy that isolates pod egress in a namespace the node mesh
// intercepts; the companion selects the same pods and allows TCP to the
// mesh outbound port. Why that port is what the CNI must see is explained
// in docs/operator.md, "Workload namespaces with default-deny egress".
//
// INVARIANT: the companion is additive. A policy with policyTypes [Egress]
// isolates the pods it selects, so a companion may exist only beside a
// policy that already isolates egress and must copy that policy's
// podSelector; the operator never isolates a pod on its own.
//
// The companion carries a controller ownerReference to its source, so source
// deletion GCs it. A source that stops isolating egress, already allows the
// port, or whose namespace joins the mesh exclusion list, has its companion
// deleted here.
type MeshEgressReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Port is the node mesh's outbound listener port (armtls-mesh
	// --outbound-port).
	Port int32

	// Excluded are the local source namespaces the mesh does not intercept
	// (armtls-mesh --exclude-source-namespaces).
	Excluded map[string]struct{}
}

func (r *MeshEgressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("networkpolicy", req.NamespacedName)

	source := &networkingv1.NetworkPolicy{}
	if err := r.Get(ctx, req.NamespacedName, source); err != nil {
		// Source gone: its companion is GC'd via the controller ownerReference.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if isMeshEgressCompanion(source) {
		return ctrl.Result{}, nil
	}

	name := meshEgressCompanionName(source.Name)
	if !r.wantsCompanion(source) {
		return ctrl.Result{}, r.deleteCompanion(ctx, source, name)
	}

	companion := &networkingv1.NetworkPolicy{Name: name, Namespace: source.Namespace}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, companion, func() error {
		if companion.UID != "" && !metav1.IsControlledBy(companion, source) {
			return errCompanionNotManaged
		}
		if companion.Labels == nil {
			companion.Labels = map[string]string{}
		}
		companion.Labels[managedByLabel] = managedByValue
		companion.Labels[meshEgressCompanionLabel] = "true"
		if err := controllerutil.SetControllerReference(source, companion, r.Scheme); err != nil {
			return err
		}
		companion.Spec = r.companionSpec(source)
		return nil
	})
	if errors.Is(err, errCompanionNotManaged) || apierrors.IsAlreadyExists(err) {
		// A policy with the companion's name exists and is not ours. Leave it
		// alone rather than fight over it; retry in case it goes away.
		l.Info("a NetworkPolicy with the companion name exists and is not controlled by this policy; not adopting",
			"companion", name)
		r.Recorder.Eventf(source, nil, corev1.EventTypeWarning, "MeshEgressPolicyConflict", "EnsureMeshEgressPolicy",
			"NetworkPolicy %s exists and is not controlled by this policy; the mesh egress companion will not be created until it is removed", name)
		return ctrl.Result{RequeueAfter: collisionRequeue}, nil
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure mesh egress companion %s/%s: %w", source.Namespace, name, err)
	}
	if op != controllerutil.OperationResultNone {
		l.Info("mesh egress companion reconciled", "companion", name, "op", string(op))
	}
	return ctrl.Result{}, nil
}

var errCompanionNotManaged = errors.New("existing NetworkPolicy is not controlled by this policy")

func (r *MeshEgressReconciler) wantsCompanion(source *networkingv1.NetworkPolicy) bool {
	if _, excluded := r.Excluded[source.Namespace]; excluded {
		return false
	}
	return slices.Contains(source.Spec.PolicyTypes, networkingv1.PolicyTypeEgress) &&
		!egressAllowsPort(source.Spec.Egress, r.Port)
}

// egressAllowsPort reports whether some egress rule already admits TCP to
// port for every destination: a rule with no peer that is unrestricted,
// allows all TCP, or names the port numerically. Anything else (named
// ports, rules with peers) is treated as not allowing it, so the companion
// errs towards existing.
func egressAllowsPort(rules []networkingv1.NetworkPolicyEgressRule, port int32) bool {
	for _, rule := range rules {
		if len(rule.To) != 0 {
			continue
		}
		if len(rule.Ports) == 0 {
			return true
		}
		for _, p := range rule.Ports {
			if p.Protocol != nil && *p.Protocol != corev1.ProtocolTCP {
				continue
			}
			if p.Port == nil {
				return true
			}
			if p.Port.Type != intstr.Int {
				continue
			}
			lo, hi := p.Port.IntVal, p.Port.IntVal
			if p.EndPort != nil {
				hi = *p.EndPort
			}
			if lo <= port && port <= hi {
				return true
			}
		}
	}
	return false
}

// companionSpec selects the pods source isolates and allows TCP to the mesh
// outbound port, with no peer.
func (r *MeshEgressReconciler) companionSpec(source *networkingv1.NetworkPolicy) networkingv1.NetworkPolicySpec {
	port := intstr.FromInt32(r.Port)
	tcp := corev1.ProtocolTCP
	return networkingv1.NetworkPolicySpec{
		PodSelector: *source.Spec.PodSelector.DeepCopy(),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
		}},
	}
}

// deleteCompanion removes the companion controlled by source, if any. Owner
// GC does not fire while the source lives, so a source that no longer needs
// a companion needs this explicit delete.
func (r *MeshEgressReconciler) deleteCompanion(ctx context.Context, source *networkingv1.NetworkPolicy, name string) error {
	companion := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, client.ObjectKey{Namespace: source.Namespace, Name: name}, companion)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get mesh egress companion %s/%s: %w", source.Namespace, name, err)
	}
	if !metav1.IsControlledBy(companion, source) {
		return nil
	}
	if err := r.Delete(ctx, companion); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete mesh egress companion %s/%s: %w", source.Namespace, name, err)
	}
	log.FromContext(ctx).Info("deleted mesh egress companion", "companion", name, "namespace", source.Namespace)
	return nil
}

func isMeshEgressCompanion(np client.Object) bool {
	_, ok := np.GetLabels()[meshEgressCompanionLabel]
	return ok
}

// meshEgressCompanionName derives the companion's name from the source's.
// A source name near the DNS-subdomain limit is truncated and suffixed with
// a hash of the full name so two long sources cannot collide.
func meshEgressCompanionName(source string) string {
	const maxLen = validation.DNS1123SubdomainMaxLength
	if len(source)+len(meshEgressCompanionSuffix) <= maxLen {
		return source + meshEgressCompanionSuffix
	}
	sum := sha256.Sum256([]byte(source))
	hash := hex.EncodeToString(sum[:4])
	keep := maxLen - len(meshEgressCompanionSuffix) - len(hash) - 1
	prefix := strings.TrimRight(source[:keep], "-.")
	return prefix + "-" + hash + meshEgressCompanionSuffix
}

func (r *MeshEgressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("mesh outbound port %d out of range", r.Port)
	}
	// Companions are filtered out of the source watch; their events still
	// reach the reconciler through Owns, keyed on the source that owns them.
	// The reconciler reads only spec, which bumps metadata.generation.
	notCompanion := predicate.NewPredicateFuncs(func(o client.Object) bool { return !isMeshEgressCompanion(o) })
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.NetworkPolicy{}, builder.WithPredicates(notCompanion, predicate.GenerationChangedPredicate{})).
		Owns(&networkingv1.NetworkPolicy{}).
		Named(meshEgressControllerName).
		Complete(r)
}
