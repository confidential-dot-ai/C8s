package podmesh

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestInvalidPeerPolicyIsRejectedBeforePodMutation(t *testing.T) {
	for name, envs := range map[string][][]corev1.EnvVar{
		"malformed": {{
			{Name: workloadclaims.MeshPeerWorkloadsEnv, Value: "worker,"},
		}},
		"valueFrom": {{
			{Name: workloadclaims.MeshPeerWorkloadsEnv, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
		}},
		"disagreement": {
			{{Name: workloadclaims.MeshPeerWorkloadsEnv, Value: "worker"}},
			{{Name: workloadclaims.MeshPeerWorkloadsEnv, Value: "router"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			pod := &corev1.Pod{}
			for _, env := range envs {
				pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
					Name: "app",
					Env:  env,
					ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt32(8080),
					}}},
				})
			}
			before := pod.DeepCopy()
			if err := ValidateWorkloadPod(pod); err == nil {
				t.Fatal("invalid peer policy passed pre-launch validation")
			}
			if err := InjectEndpoint(pod, "mesh"); err == nil {
				t.Fatal("invalid peer policy passed injection")
			}
			if !reflect.DeepEqual(before, pod) {
				t.Fatal("rejection mutated the pod")
			}
		})
	}
}

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
