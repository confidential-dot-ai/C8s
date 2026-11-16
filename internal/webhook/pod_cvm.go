package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// AnnotationPodCVM opts a Pod into guest-owned execution and mesh injection.
// The same key labels and taints the provider's virtual node.
const AnnotationPodCVM = "confidential.ai/pod-cvm"

// podCVMRouter is the half of Pod CVM admission the two webhooks answer
// differently: the mutator adds the Pod's routing to the Pod CVM node and
// answers with the patch, the validator requires the routing already there.
type podCVMRouter interface {
	admitRouting(req admission.Request, pod *corev1.Pod) admission.Response
}

type mutatingPodCVM struct{}

type validatingPodCVM struct{}

func (mutatingPodCVM) admitRouting(req admission.Request, pod *corev1.Pod) admission.Response {
	if err := addPodCVMRouting(pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}

func (validatingPodCVM) admitRouting(_ admission.Request, pod *corev1.Pod) admission.Response {
	if err := requirePodCVMRouting(pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	return admission.Allowed("Pod CVM workload and scheduling are valid")
}

func handlePodCVM(req admission.Request, pod *corev1.Pod, decoder admission.Decoder, cfg Config, router podCVMRouter) (admission.Response, bool) {
	old, opted, err := podCVMAdmission(req, pod, decoder)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err), true
	}
	if !opted {
		if err := rejectUnrequestedPodCVMRouting(pod, cfg.PodCVMProviderEnabled); err != nil {
			return admission.Errored(http.StatusBadRequest, err), true
		}
		return admission.Response{}, false
	}
	if err := validatePodCVMRequest(req, old, pod, cfg); err != nil {
		return admission.Errored(http.StatusBadRequest, err), true
	}
	if old != nil && reflect.DeepEqual(old.Spec, pod.Spec) {
		return admission.Allowed("Pod CVM workload unchanged"), true
	}
	return router.admitRouting(req, pod), true
}

func podCVMAdmission(req admission.Request, pod *corev1.Pod, decoder admission.Decoder) (*corev1.Pod, bool, error) {
	opted, err := podCVMOptedIn(pod)
	if err != nil {
		return nil, false, err
	}
	if req.Operation != admissionv1.Update {
		return nil, opted, nil
	}
	if len(req.OldObject.Raw) == 0 {
		if opted {
			return nil, false, errors.New("pod CVM update requires the previous Pod")
		}
		return nil, opted, nil
	}
	old := &corev1.Pod{}
	if err := decoder.DecodeRaw(req.OldObject, old); err != nil {
		return nil, false, err
	}
	previous, err := podCVMOptedIn(old)
	if err != nil {
		return nil, false, err
	}
	if previous != opted {
		return nil, false, errors.New("pod CVM execution mode is fixed when the Pod is created")
	}
	return old, opted, nil
}

func podCVMOptedIn(pod *corev1.Pod) (bool, error) {
	switch pod.Annotations[AnnotationPodCVM] {
	case "true":
		return true, nil
	case "", "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", AnnotationPodCVM)
	}
}

func rejectUnrequestedPodCVMRouting(pod *corev1.Pod, providerEnabled bool) error {
	if pod.Spec.NodeSelector[AnnotationPodCVM] == "true" {
		return fmt.Errorf("pod CVM node selection requires %s=true", AnnotationPodCVM)
	}
	for _, toleration := range pod.Spec.Tolerations {
		if toleration.Key == AnnotationPodCVM || (providerEnabled && toleration.Key == "" && toleration.Operator == corev1.TolerationOpExists &&
			(toleration.Effect == "" || toleration.Effect == corev1.TaintEffectNoSchedule)) {
			return fmt.Errorf("tolerating the Pod CVM node requires %s=true", AnnotationPodCVM)
		}
	}
	return nil
}

func validatePodCVMRequest(req admission.Request, old, pod *corev1.Pod, cfg Config) error {
	if req.SubResource != "" && req.SubResource != "status" {
		return fmt.Errorf("pod CVM does not support the %s subresource", req.SubResource)
	}
	if err := rejectNamespaceMismatch(pod, req.Namespace); err != nil {
		return err
	}
	if err := workloadclaims.ValidateWorkloadLabel(pod); err != nil {
		return err
	}
	if hasInjectionDetailAnnotations(pod.Annotations) || pod.Annotations[AnnotationInjected] != "" {
		return errors.New("pod CVM uses guest-owned mesh and does not accept host-side injection annotations")
	}
	if err := rejectCredentialPathAnnotations(pod); err != nil {
		return err
	}
	if old != nil {
		if err := validatePodCVMUpdate(old, pod); err != nil {
			return err
		}
		if reflect.DeepEqual(old.Spec, pod.Spec) {
			return nil
		}
	}
	if !cfg.PodCVMProviderEnabled {
		return errors.New("pod CVM provider is disabled on this cluster")
	}
	if req.Operation == admissionv1.Create && pod.Spec.NodeName != "" {
		return errors.New("pod CVM must be placed by the Kubernetes scheduler; nodeName is not allowed on CREATE")
	}
	validationPod := pod.DeepCopy()
	if validationPod.Namespace == "" {
		validationPod.Namespace = req.Namespace
	}
	return podlaunch.ValidateProviderPod(validationPod)
}

func validatePodCVMUpdate(old, pod *corev1.Pod) error {
	if err := rejectIdentityChange(old, pod); err != nil {
		return err
	}
	// The provider freezes the client document when it first records the Pod.
	if old.Annotations[workloadclaims.AnnotationClientDocument] != pod.Annotations[workloadclaims.AnnotationClientDocument] {
		return fmt.Errorf("the %s annotation is fixed when the Pod is created", workloadclaims.AnnotationClientDocument)
	}
	if old.Spec.NodeName == "" {
		return nil
	}
	if !reflect.DeepEqual(old.Spec, pod.Spec) {
		return errors.New("a scheduled Pod CVM workload is immutable; replace the Pod to change it")
	}
	return rejectPodCVMFieldRefChanges(old, pod)
}

func rejectPodCVMFieldRefChanges(old, pod *corev1.Pod) error {
	for _, container := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		for _, env := range container.Env {
			if env.ValueFrom == nil || env.ValueFrom.FieldRef == nil {
				continue
			}
			field := env.ValueFrom.FieldRef.FieldPath
			for name, previous := range map[string]map[string]string{"labels": old.Labels, "annotations": old.Annotations} {
				current := pod.Labels
				if name == "annotations" {
					current = pod.Annotations
				}
				prefix := "metadata." + name
				changed := field == prefix && !reflect.DeepEqual(previous, current)
				if key, ok := strings.CutPrefix(field, prefix+"['"); ok {
					if key, ok = strings.CutSuffix(key, "']"); ok {
						changed = previous[key] != current[key]
					}
				}
				if changed {
					return fmt.Errorf("scheduled Pod CVM field reference %s is immutable", field)
				}
			}
		}
	}
	return nil
}

// podCVMToleration is the only toleration of the Pod CVM node a workload may
// carry.
func podCVMToleration() corev1.Toleration {
	return corev1.Toleration{
		Key:      AnnotationPodCVM,
		Operator: corev1.TolerationOpEqual,
		Value:    "true",
		Effect:   corev1.TaintEffectNoSchedule,
	}
}

// podCVMRouting reports which halves of the Pod CVM routing the Pod carries,
// refusing a selector or a toleration that names the node on other terms.
func podCVMRouting(pod *corev1.Pod) (hasSelector, hasToleration bool, err error) {
	value, hasSelector := pod.Spec.NodeSelector[AnnotationPodCVM]
	if hasSelector && value != "true" {
		return false, false, errors.New("pod CVM node selector conflicts with the requested execution mode")
	}
	for _, toleration := range pod.Spec.Tolerations {
		if toleration.Key != AnnotationPodCVM {
			continue
		}
		if !reflect.DeepEqual(toleration, podCVMToleration()) {
			return false, false, errors.New("pod CVM requires its exact NoSchedule toleration")
		}
		hasToleration = true
	}
	return hasSelector, hasToleration, nil
}

func addPodCVMRouting(pod *corev1.Pod) error {
	_, hasToleration, err := podCVMRouting(pod)
	if err != nil {
		return err
	}
	if pod.Spec.NodeSelector == nil {
		pod.Spec.NodeSelector = make(map[string]string)
	}
	pod.Spec.NodeSelector[AnnotationPodCVM] = "true"
	if !hasToleration {
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, podCVMToleration())
	}
	return nil
}

func requirePodCVMRouting(pod *corev1.Pod) error {
	hasSelector, hasToleration, err := podCVMRouting(pod)
	if err != nil {
		return err
	}
	if !hasSelector || !hasToleration {
		return errors.New("pod CVM is missing its required node selector or toleration")
	}
	return nil
}
