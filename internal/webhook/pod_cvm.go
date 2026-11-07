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

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// AnnotationPodCVM opts a Pod into guest-owned execution and mesh injection.
// The same key labels and taints the provider's virtual node.
const AnnotationPodCVM = "confidential.ai/pod-cvm"

func handlePodCVM(req admission.Request, pod *corev1.Pod, decoder admission.Decoder, cfg Config, mutate bool) (admission.Response, bool) {
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
	if err := routePodCVM(pod, mutate); err != nil {
		return admission.Errored(http.StatusBadRequest, err), true
	}
	if !mutate {
		return admission.Allowed("Pod CVM workload and scheduling are valid"), true
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err), true
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, raw), true
}

func podCVMAdmission(req admission.Request, pod *corev1.Pod, decoder admission.Decoder) (*corev1.Pod, bool, error) {
	opted, err := podCVMOptedIn(pod)
	if err != nil {
		return nil, false, err
	}
	var old *corev1.Pod
	if req.Operation == admissionv1.Update {
		if len(req.OldObject.Raw) == 0 {
			if opted {
				return nil, false, errors.New("pod CVM update requires the previous Pod")
			}
		} else {
			old = &corev1.Pod{}
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
		}
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
	if err := validateWorkloadLabel(pod); err != nil {
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
	return launchconfig.ValidateProviderPod(validationPod)
}

func validatePodCVMUpdate(old, pod *corev1.Pod) error {
	if err := rejectIdentityChange(old, pod); err != nil {
		return err
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

func routePodCVM(pod *corev1.Pod, mutate bool) error {
	value, hasSelector := pod.Spec.NodeSelector[AnnotationPodCVM]
	if hasSelector && value != "true" {
		return errors.New("pod CVM node selector conflicts with the requested execution mode")
	}
	want := corev1.Toleration{Key: AnnotationPodCVM, Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule}
	hasToleration := false
	for _, toleration := range pod.Spec.Tolerations {
		if toleration.Key != AnnotationPodCVM {
			continue
		}
		if !reflect.DeepEqual(toleration, want) {
			return errors.New("pod CVM requires its exact NoSchedule toleration")
		}
		hasToleration = true
	}
	if !mutate && (!hasSelector || !hasToleration) {
		return errors.New("pod CVM is missing its required node selector or toleration")
	}
	if mutate {
		if pod.Spec.NodeSelector == nil {
			pod.Spec.NodeSelector = make(map[string]string)
		}
		pod.Spec.NodeSelector[AnnotationPodCVM] = "true"
		if !hasToleration {
			pod.Spec.Tolerations = append(pod.Spec.Tolerations, want)
		}
	}
	return nil
}
