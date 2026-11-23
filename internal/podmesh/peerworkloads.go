package podmesh

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// PeerWorkloadEnv derives the endpoint's requirement from literal workload
// environment. The node checks the final environments independently of injection.
func PeerWorkloadEnv(pod *corev1.Pod) ([]corev1.EnvVar, error) {
	var env []string
	for _, c := range WorkloadContainers(pod) {
		for _, item := range c.Env {
			if item.Name == workloadclaims.MeshPeerWorkloadsEnv {
				if item.ValueFrom != nil {
					return nil, fmt.Errorf("%s must be a literal value", item.Name)
				}
				env = append(env, item.Name+"="+item.Value)
			}
		}
	}
	// Each pod has one endpoint; multiple declarations must agree.
	value, found := "", false
	for _, item := range env {
		next, err := workloadclaims.MeshPeerWorkloads([]string{item})
		if err != nil {
			return nil, err
		}
		if found && next != value {
			return nil, fmt.Errorf("containers disagree on %s", workloadclaims.MeshPeerWorkloadsEnv)
		}
		value, found = next, true
	}
	if value == "" {
		return nil, nil
	}
	return []corev1.EnvVar{{Name: workloadclaims.MeshPeerWorkloadsEnv, Value: value}}, nil
}
