package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/confidential-dot-ai/confidential-kubernetes/api/v1alpha2"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/webhook"
)

// resolveWorkloadCWID maps the CW's spec.workloadRef to the cw id stamped on
// the referenced workload's pod template (confidential.ai/cw). That id — not
// the CW object's own metadata.name — is what the webhook writes onto member
// pods, so aggregating by it lets a CW whose name differs from the workload's
// cw id still select its pods (M-09: the declared workloadRef was previously
// ignored, and matching used cw.Name). Falls back to cw.Name when the ref is
// unset/unsupported, the workload is gone or unreadable, or it carries no cw
// id — preserving the prior behavior for the common name==id case.
func (r *ConfidentialWorkloadReconciler) resolveWorkloadCWID(ctx context.Context, cw *v1alpha2.ConfidentialWorkload) string {
	ref := cw.Spec.WorkloadRef
	obj := newWorkloadObject(ref.Kind)
	if obj == nil || ref.Name == "" {
		return cw.Name
	}
	if err := r.Get(ctx, client.ObjectKey{Namespace: cw.Namespace, Name: ref.Name}, obj); err != nil {
		return cw.Name
	}
	tmpl := podTemplate(obj)
	if tmpl == nil {
		return cw.Name
	}
	if id := tmpl.Annotations[webhook.AnnotationWorkload]; id != "" {
		return id
	}
	return cw.Name
}

// statusMirrorRequeue keeps the per-pod summary loosely current without
// hammering the API server. The reconciler watches CW only (not pods), so
// pod-readiness transitions are picked up at this cadence.
const statusMirrorRequeue = 30 * time.Second

// ConfidentialWorkloadReconciler is a status-mirror controller. It lists
// pods carrying confidential.ai/cw=<cwName> in the CW's namespace and
// aggregates a Total / Attested summary into status. No security gates
// live here.
type ConfidentialWorkloadReconciler struct {
	client.Client
}

func (r *ConfidentialWorkloadReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("cwl", req.NamespacedName)

	var cw v1alpha2.ConfidentialWorkload
	if err := r.Get(ctx, req.NamespacedName, &cw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	previous := cw.Status.DeepCopy()

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(cw.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list pods: %w", err)
	}

	matchID := r.resolveWorkloadCWID(ctx, &cw)

	summary := summarizeWorkloadAttestation(pods.Items, matchID)
	cw.Status.AttestationSummary = &summary
	cw.Status.ObservedGeneration = cw.Generation

	cond := metav1.Condition{
		Type:               v1alpha2.ConditionAttested,
		ObservedGeneration: cw.Generation,
	}
	switch {
	case summary.Total == 0:
		cond.Status = metav1.ConditionUnknown
		cond.Reason = "NoPods"
		cond.Message = "no pods carry the confidential.ai/cw annotation"
	case summary.Attested == summary.Total:
		cond.Status = metav1.ConditionTrue
		cond.Reason = "AllAttested"
		cond.Message = fmt.Sprintf("%d/%d pods attested", summary.Attested, summary.Total)
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "PendingAttestation"
		cond.Message = fmt.Sprintf("%d/%d pods attested", summary.Attested, summary.Total)
	}
	meta.SetStatusCondition(&cw.Status.Conditions, cond)

	if equality.Semantic.DeepEqual(previous, &cw.Status) {
		return ctrl.Result{RequeueAfter: statusMirrorRequeue}, nil
	}
	if err := r.Status().Update(ctx, &cw); err != nil {
		return ctrl.Result{}, fmt.Errorf("status update: %w", err)
	}

	l.V(1).Info("status mirrored", "total", summary.Total, "attested", summary.Attested)
	return ctrl.Result{RequeueAfter: statusMirrorRequeue}, nil
}

func summarizeWorkloadAttestation(pods []corev1.Pod, matchID string) v1alpha2.AttestationSummary {
	summary := v1alpha2.AttestationSummary{}
	for i := range pods {
		pod := &pods[i]
		if pod.Annotations[webhook.AnnotationWorkload] != matchID {
			continue
		}
		summary.Total++
		if isPodReady(pod) {
			summary.Attested++
		}
	}
	return summary
}

// isPodReady is the heuristic for "this pod has attested": the kubelet has
// reported PodReady, which means the c8s-cert-wait gate init container exited
// — and that only happens after a successful attestation round-trip with CDS
// wrote the issued cert to disk (the gate blocks on the cert file).
func isPodReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (r *ConfidentialWorkloadReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.ConfidentialWorkload{}).
		Named("confidentialworkload-status-mirror").
		Complete(r)
}
