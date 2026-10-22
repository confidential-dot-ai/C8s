// Package podmesh defines the platform endpoint shared by injected and guest Pods.
package podmesh

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	// CertVolumeName is private to the platform endpoint and credential producer.
	CertVolumeName = "c8s-certs"
	CertDir        = workloadclaims.MemberCertDir
	CertFile       = "tls.crt"
	KeyFile        = "tls.key"
	CAFile         = "ca.crt"
)

// Endpoint is a capability-free native sidecar. Startup does not wait for its
// credentials: its measured start is what authorizes their issuance.
func Endpoint(image string, probes []string) corev1.Container {
	always := corev1.ContainerRestartPolicyAlways
	var env []corev1.EnvVar
	if len(probes) > 0 {
		env = []corev1.EnvVar{{Name: workloadclaims.MeshProbesEnv, Value: workloadclaims.JoinMeshProbePaths(probes)}}
	}
	return corev1.Container{
		Name:            workloadclaims.MeshContainerName,
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		RestartPolicy:   &always,
		Args:            []string{"--cert-path=" + CertDir + "/" + CertFile, "--key-path=" + CertDir + "/" + KeyFile, "--ca-path=" + CertDir + "/" + CAFile},
		Env:             env,
		VolumeMounts:    []corev1.VolumeMount{{Name: CertVolumeName, MountPath: CertDir, ReadOnly: true}},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: new(false), ReadOnlyRootFilesystem: new(true), RunAsNonRoot: new(true),
			RunAsUser: new(int64(workloadclaims.MeshUID)), RunAsGroup: new(int64(workloadclaims.MeshUID)),
			Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		StartupProbe:   endpointProbe("/startupz", 1, 60),
		ReadinessProbe: endpointProbe("/readyz", 5, 3),
	}
}

func endpointProbe(path string, period, threshold int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:  corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: path, Port: intstr.FromInt32(workloadclaims.MeshHealthPort), Scheme: corev1.URISchemeHTTP}},
		PeriodSeconds: period, TimeoutSeconds: 1, SuccessThreshold: 1, FailureThreshold: threshold,
	}
}

// ValidateWorkloadPod reserves the platform shape before guest injection.
func ValidateWorkloadPod(pod *corev1.Pod) error {
	if pod.Namespace == workloadclaims.RouterNamespace {
		return fmt.Errorf("pod namespace %q is reserved for the platform router", pod.Namespace)
	}
	if pod.Spec.ShareProcessNamespace != nil && *pod.Spec.ShareProcessNamespace {
		return fmt.Errorf("shareProcessNamespace exposes the endpoint's private credentials")
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == CertVolumeName {
			return fmt.Errorf("volume %q is reserved for the platform endpoint", v.Name)
		}
	}
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if workloadclaims.IsInjectedContainerName(c.Name) {
			return fmt.Errorf("container name %q is reserved for the platform", c.Name)
		}
		for _, m := range c.VolumeMounts {
			if m.Name == CertVolumeName {
				return fmt.Errorf("container %q may not mount the private credential volume", c.Name)
			}
		}
		for _, probe := range []*corev1.Probe{c.StartupProbe, c.ReadinessProbe, c.LivenessProbe} {
			if probe != nil && probe.HTTPGet != nil && probe.HTTPGet.Host != "" {
				return fmt.Errorf("container %q probe must target its own Pod through the mesh endpoint", c.Name)
			}
		}
		for _, p := range c.Ports {
			if isMeshPort(p.ContainerPort) {
				return fmt.Errorf("container %q port %d is reserved for the mesh", c.Name, p.ContainerPort)
			}
		}
	}
	if err := RejectRenderedProbeInput(pod); err != nil {
		return err
	}
	return ValidateProbes(pod)
}

// InjectEndpoint prepends only the endpoint. The guest owns issuance; neither
// a get-cert sidecar nor its node-service mounts belong in this Pod.
func InjectEndpoint(pod *corev1.Pod, image string) error {
	if err := ValidateWorkloadPod(pod); err != nil {
		return err
	}
	probes := RewriteProbes(pod)
	pod.Spec.InitContainers = append([]corev1.Container{Endpoint(image, probes)}, pod.Spec.InitContainers...)
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: CertVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}})
	pod.Spec.EnableServiceLinks = new(false)
	pod.Spec.AutomountServiceAccountToken = new(false)
	return nil
}
