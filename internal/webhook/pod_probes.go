package webhook

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
)

// A member pod's probes are rewritten and validated by internal/podmesh, the
// one rule the node and guest endpoints forward by, so the webhooks and the
// endpoints cannot drift apart. The webhooks add only their own error class.

// rewriteWorkloadProbes moves every HTTP probe of the pod's own containers onto
// the endpoint's health port and returns the targets it rendered, in the order
// the endpoint is given them.
func rewriteWorkloadProbes(pod *corev1.Pod) []string {
	return podmesh.RewriteProbes(pod)
}

// rejectRenderedProbeInput reserves the forwarding route for initial mutation.
func rejectRenderedProbeInput(pod *corev1.Pod) error {
	if err := podmesh.RejectRenderedProbeInput(pod); err != nil {
		return fmt.Errorf("%w: %v", errInvalidInjectionAnnotation, err)
	}
	return nil
}

// rejectUnforwardableProbes refuses probes and hooks the endpoint cannot forward.
func rejectUnforwardableProbes(pod *corev1.Pod) error {
	if err := podmesh.ValidateProbes(pod); err != nil {
		return fmt.Errorf("%w: %v", errInvalidInjectionAnnotation, err)
	}
	return nil
}

// authorContainers are the pod's own containers, init then regular, without
// the platform containers the injector owns.
func authorContainers(pod *corev1.Pod) []*corev1.Container {
	return podmesh.WorkloadContainers(pod)
}
