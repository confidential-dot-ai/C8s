package webhook

import (
	"fmt"
	"maps"

	corev1 "k8s.io/api/core/v1"
)

// selectConfidentialNodes adds this cluster's confidential-node labels to the
// pod's nodeSelector, which Kubernetes requires together with the nodeAffinity
// the pod declares itself.
func selectConfidentialNodes(pod *corev1.Pod, nodeLabels map[string]string) {
	if len(nodeLabels) == 0 {
		return
	}
	if pod.Spec.NodeSelector == nil {
		pod.Spec.NodeSelector = make(map[string]string, len(nodeLabels))
	}
	maps.Copy(pod.Spec.NodeSelector, nodeLabels)
}

// rejectPlainNodePlacement refuses a pod that does not select this cluster's
// confidential nodes: a node outside them runs no C8s node agent.
func rejectPlainNodePlacement(pod *corev1.Pod, nodeLabels map[string]string) error {
	for key, value := range nodeLabels {
		if selected := pod.Spec.NodeSelector[key]; selected != value {
			return fmt.Errorf("%w: nodeSelector %s=%s, want %s=%s",
				errUninjectedPod, key, selected, key, value)
		}
	}
	return nil
}

// rejectNodeSelectorConflict refuses a pod that selects a confidential-node
// label under another value: the injector replaces no value a pod chose.
func rejectNodeSelectorConflict(pod *corev1.Pod, nodeLabels map[string]string) error {
	for key, value := range nodeLabels {
		if selected, ok := pod.Spec.NodeSelector[key]; ok && selected != value {
			return fmt.Errorf("%w: nodeSelector %s=%s contradicts %s=%s, which this cluster's confidential nodes carry",
				errInvalidInjectionAnnotation, key, selected, key, value)
		}
	}
	return nil
}
