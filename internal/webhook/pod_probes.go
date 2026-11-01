package webhook

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
)

func rewriteWorkloadProbes(pod *corev1.Pod) []string { return podmesh.RewriteProbes(pod) }

func workloadProbeContainers(pod *corev1.Pod) []*corev1.Container {
	return podmesh.WorkloadContainers(pod)
}

func rejectRenderedProbeInput(pod *corev1.Pod) error {
	if err := podmesh.RejectRenderedProbeInput(pod); err != nil {
		return fmt.Errorf("%w: %w", errInvalidInjectionAnnotation, err)
	}
	return nil
}

func rejectUnforwardableProbes(pod *corev1.Pod) error {
	if err := podmesh.ValidateProbes(pod); err != nil {
		return fmt.Errorf("%w: %w", errInvalidInjectionAnnotation, err)
	}
	return nil
}
