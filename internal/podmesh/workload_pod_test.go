package podmesh

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Every platform-owned shape of a workload Pod is refused before the guest
// injects its endpoint.
func TestWorkloadPodRefusesPlatformShapes(t *testing.T) {
	share := true
	tests := []struct {
		name  string
		spoil func(*corev1.Pod)
		want  string
	}{
		{"router namespace", func(p *corev1.Pod) { p.Namespace = workloadclaims.RouterNamespace }, "reserved for the platform router"},
		{"shared process namespace", func(p *corev1.Pod) { p.Spec.ShareProcessNamespace = &share }, "shareProcessNamespace"},
		{"credential volume", func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "data"}, {Name: CertVolumeName}}
		}, "volume \"c8s-certs\" is reserved"},
		{"injected container name", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: workloadclaims.MeshContainerName}}
		}, "is reserved for the platform"},
		{"credential mount", func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data"}, {Name: CertVolumeName}}
		}, "may not mount the private credential volume"},
		{"rendered probe path", func(p *corev1.Pod) {
			p.Spec.Containers[0].ReadinessProbe.HTTPGet.Path = workloadclaims.MeshProbePrefix + "8080/health"
		}, "reserved for generated probes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := workloadPod()
			tc.spoil(pod)
			err := ValidateWorkloadPod(pod)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	if err := ValidateWorkloadPod(workloadPod()); err != nil {
		t.Fatalf("an ordinary workload Pod was refused: %v", err)
	}
}

// Only a port number a TCP listener can use, outside the platform's own
// ports, is a guest ingress port.
func TestIngressPortsRefuseInvalidAndPlatformPorts(t *testing.T) {
	for _, port := range []int32{0, 65536, workloadclaims.PodStatusPort, workloadclaims.MeshHealthPort} {
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: port}}}}}}
		if ports, err := IngressPorts(pod); err == nil {
			t.Fatalf("port %d gave ingress ports %v", port, ports)
		}
	}
}

// A probe with no path reaches the application's root; one the endpoint
// cannot forward is left for validation to refuse.
func TestRewriteProbesDefaultsThePathAndSkipsUnforwardableProbes(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
		Name:           "app",
		StartupProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080)}}},
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromInt32(8443), Scheme: corev1.URISchemeHTTPS}}},
	}}}}
	rendered := RewriteProbes(pod)
	want := workloadclaims.MeshProbePath(8080, "/")
	if !slices.Equal(rendered, []string{want}) {
		t.Fatalf("rendered = %v, want [%s]", rendered, want)
	}
	if get := pod.Spec.Containers[0].StartupProbe.HTTPGet; get.Path != want || get.Port.IntVal != workloadclaims.MeshHealthPort {
		t.Fatalf("startup probe = %+v", get)
	}
	if get := pod.Spec.Containers[0].ReadinessProbe.HTTPGet; get.Path != "/ready" || get.Port.IntVal != 8443 {
		t.Fatalf("an HTTPS probe was rewritten: %+v", get)
	}
}

func workloadPod() *corev1.Pod {
	return &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
		Name:           "app",
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health", Port: intstr.FromInt32(8080)}}},
	}}}}
}
