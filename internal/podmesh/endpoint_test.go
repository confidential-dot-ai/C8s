package podmesh

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestGuestEndpointPrecedesWorkloadsAndOwnsPrivateRAMVolume(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init"}},
		Containers:     []corev1.Container{{Name: "app", ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health", Port: intstr.FromInt32(8080)}}}}},
	}}
	if err := InjectEndpoint(pod, "registry/mesh@sha256:measured"); err != nil {
		t.Fatal(err)
	}
	endpoint := pod.Spec.InitContainers[0]
	if endpoint.Name != workloadclaims.MeshContainerName || pod.Spec.InitContainers[1].Name != "init" || endpoint.RestartPolicy == nil || *endpoint.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("native sidecar order = %+v", pod.Spec.InitContainers)
	}
	if len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].Name != CertVolumeName || pod.Spec.Volumes[0].EmptyDir == nil || pod.Spec.Volumes[0].EmptyDir.Medium != corev1.StorageMediumMemory {
		t.Fatalf("private volume = %+v", pod.Spec.Volumes)
	}
	if len(endpoint.VolumeMounts) != 1 || !endpoint.VolumeMounts[0].ReadOnly || len(pod.Spec.Containers[0].VolumeMounts) != 0 {
		t.Fatal("private credentials reached a workload or writable endpoint mount")
	}
	probe := pod.Spec.Containers[0].ReadinessProbe.HTTPGet
	if probe.Port.IntVal != workloadclaims.MeshHealthPort || len(endpoint.Env) != 1 || !slices.Contains(workloadclaims.SplitMeshProbePaths(endpoint.Env[0].Value), probe.Path) {
		t.Fatalf("probe forwarding = %+v, endpoint env %+v", probe, endpoint.Env)
	}
	if *pod.Spec.AutomountServiceAccountToken || *pod.Spec.EnableServiceLinks {
		t.Fatal("guest inherited node service discovery or credentials")
	}
}

func TestGuestProbeCannotAskKubeletToReachAGuestService(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Host: "127.0.0.1", Path: "/attest", Port: intstr.FromInt32(8080)}}}}}}}
	if err := InjectEndpoint(pod, "measured"); err == nil {
		t.Fatal("explicit-host probe bypassed guest protection")
	}
}
