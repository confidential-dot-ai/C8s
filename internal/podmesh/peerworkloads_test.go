package podmesh

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestPeerPolicyInjectionAndValidation(t *testing.T) {
	for _, value := range []string{"worker", "worker,router", "", "worker,", ",worker", " worker", "worker,worker", strings.Repeat("a,", 32) + "b"} {
		t.Run(value, func(t *testing.T) {
			pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: workloadclaims.MeshPeerWorkloadsEnv, Value: value}}}}}}
			_, parseErr := workloadclaims.ParseMeshPeerWorkloads(value)
			err := InjectEndpoint(pod, "mesh")
			if (err == nil) != (parseErr == nil) {
				t.Fatalf("injection %v differs from parser %v", err, parseErr)
			}
			if err == nil && value != "" {
				if !slices.Contains(pod.Spec.InitContainers[0].Env, corev1.EnvVar{Name: workloadclaims.MeshPeerWorkloadsEnv, Value: value}) {
					t.Fatal("endpoint omitted the application requirement")
				}
			}
		})
	}
	if _, err := workloadclaims.MeshPeerWorkloads([]string{"C8S_MESH_PEER_WORKLOADS=worker", "C8S_MESH_PEER_WORKLOADS="}); err == nil {
		t.Fatal("duplicate runtime value was accepted")
	}
}
