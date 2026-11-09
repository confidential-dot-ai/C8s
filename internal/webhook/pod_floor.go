package webhook

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
)

// rejectRootContainers refuses a container the author runs as root: a worker's
// privilege floor refuses one outside every platform role.
func rejectRootContainers(pod *corev1.Pod) error {
	for _, c := range podmesh.WorkloadContainers(pod) {
		if runsAsRoot(pod, c) {
			return fmt.Errorf("container %q has runAsUser: 0, and a C8s node refuses a container that runs as root; set securityContext.runAsUser to a nonzero uid", c.Name)
		}
	}
	return nil
}

func runsAsRoot(pod *corev1.Pod, c *corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
		return *c.SecurityContext.RunAsUser == 0
	}
	return pod.Spec.SecurityContext != nil &&
		pod.Spec.SecurityContext.RunAsUser != nil &&
		*pod.Spec.SecurityContext.RunAsUser == 0
}
