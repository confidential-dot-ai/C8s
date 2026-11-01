package podmesh

import (
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// A member pod's ruleset redirects every application port into the mesh
// listener, which answers an armTLS handshake and not an HTTP request, so the
// kubelet's plaintext probe of an application port can never pass. The injector
// moves each such probe onto the endpoint's health port, under a path naming the
// port and path it reaches, and the endpoint forwards that path inside the pod
// and answers with the application's status code alone (cmd/armtls-mesh).
//
// The rewrite is idempotent: a probe already on a rendered path is the target it
// names, so the validator derives the same endpoint shape from a stored pod.

// RewriteProbes moves every HTTP probe of the pod's own containers onto
// the endpoint's health port and returns the targets it rendered, in the order
// the endpoint is given them.
func RewriteProbes(pod *corev1.Pod) []string {
	var rendered []string
	for _, c := range WorkloadContainers(pod) {
		for _, probe := range []*corev1.Probe{c.StartupProbe, c.ReadinessProbe, c.LivenessProbe} {
			target := meshProbeTarget(c, probe)
			if target == "" {
				continue
			}
			probe.HTTPGet.Port = intstr.FromInt32(workloadclaims.MeshHealthPort)
			probe.HTTPGet.Path = target
			if !slices.Contains(rendered, target) {
				rendered = append(rendered, target)
			}
		}
	}
	return rendered
}

// RejectRenderedProbeInput reserves the forwarding route for initial mutation.
func RejectRenderedProbeInput(pod *corev1.Pod) error {
	for _, c := range WorkloadContainers(pod) {
		for _, probe := range []*corev1.Probe{c.StartupProbe, c.ReadinessProbe, c.LivenessProbe} {
			if probesThePod(probe) && strings.HasPrefix(probe.HTTPGet.Path, workloadclaims.MeshProbePrefix) {
				return fmt.Errorf("container %q: probe path %q is reserved for generated probes; supply the application's HTTP path and port", c.Name, probe.HTTPGet.Path)
			}
		}
	}
	return nil
}

// ValidateProbes refuses probes and hooks the endpoint cannot forward.
func ValidateProbes(pod *corev1.Pod) error {
	for _, c := range WorkloadContainers(pod) {
		if err := rejectContainerProbeShapes(c); err != nil {
			return fmt.Errorf("container %q: %w", c.Name, err)
		}
	}
	return nil
}

func rejectContainerProbeShapes(c *corev1.Container) error {
	if c.Lifecycle != nil {
		for name, hook := range map[string]*corev1.LifecycleHandler{
			"postStart": c.Lifecycle.PostStart,
			"preStop":   c.Lifecycle.PreStop,
		} {
			if hook != nil && hook.HTTPGet != nil {
				return fmt.Errorf("HTTP lifecycle hook %s cannot be forwarded; use an HTTP startup, readiness or liveness probe", name)
			}
		}
	}
	for _, probe := range []*corev1.Probe{c.StartupProbe, c.ReadinessProbe, c.LivenessProbe} {
		if probe == nil {
			continue
		}
		if probe.TCPSocket != nil || probe.GRPC != nil {
			return fmt.Errorf("tcpSocket and grpc probes cannot be forwarded; use an HTTP probe with an application path and port")
		}
		if !probesThePod(probe) {
			continue
		}
		get := probe.HTTPGet
		if len(get.HTTPHeaders) > 0 {
			return fmt.Errorf("forwarded probes require empty httpHeaders")
		}
		if time.Duration(probe.TimeoutSeconds)*time.Second > workloadclaims.MeshProbeTimeout {
			return fmt.Errorf("forwarded probe timeoutSeconds exceeds the %s budget", workloadclaims.MeshProbeTimeout)
		}
		if get.Scheme != "" && get.Scheme != corev1.URISchemeHTTP {
			return fmt.Errorf("probe scheme %s cannot be forwarded; use an HTTP probe", get.Scheme)
		}
		if renderedProbe(get) {
			continue
		}
		if _, err := forwardableProbePort(c, get); err != nil {
			return err
		}
	}
	return nil
}

// meshProbeTarget is the health-port path that answers probe: the one it
// already carries, the one its application target renders, or "" for a probe
// the injector leaves alone.
func meshProbeTarget(c *corev1.Container, probe *corev1.Probe) string {
	if !probesThePod(probe) {
		return ""
	}
	if renderedProbe(probe.HTTPGet) {
		return probe.HTTPGet.Path
	}
	port, err := forwardableProbePort(c, probe.HTTPGet)
	if err != nil {
		// Refused by ValidateProbes before either injector changes the Pod.
		return ""
	}
	return workloadclaims.MeshProbePath(port, probedPath(probe.HTTPGet.Path))
}

// probesThePod reports whether the kubelet aims probe into the pod's network
// namespace. A probe naming a host is dialled from the node to that host, and
// never enters the pod.
func probesThePod(probe *corev1.Probe) bool {
	return probe != nil && probe.HTTPGet != nil && probe.HTTPGet.Host == ""
}

// renderedProbe reports whether get is already the injector's own rewrite.
func renderedProbe(get *corev1.HTTPGetAction) bool {
	if get.Port != intstr.FromInt32(workloadclaims.MeshHealthPort) {
		return false
	}
	_, _, err := workloadclaims.ParseMeshProbePath(get.Path)
	return err == nil
}

// forwardableProbePort is the application port get reaches, for a probe the
// endpoint can forward inside the pod.
func forwardableProbePort(c *corev1.Container, get *corev1.HTTPGetAction) (int32, error) {
	if get.Scheme != "" && get.Scheme != corev1.URISchemeHTTP {
		return 0, fmt.Errorf("probe scheme %s cannot be forwarded by the pod's mesh endpoint, which forwards an HTTP probe to the pod's loopback", get.Scheme)
	}
	port, err := probedContainerPort(c, get.Port)
	if err != nil {
		return 0, err
	}
	if isMeshPort(port) {
		return 0, fmt.Errorf("probe port %d is a mesh port, not an application port", port)
	}
	if !workloadclaims.ForwardableMeshProbePath(probedPath(get.Path)) {
		return 0, fmt.Errorf("probe path %q must be an absolute, clean path of unreserved characters to be forwarded by the pod's mesh endpoint", get.Path)
	}
	return port, nil
}

// probedContainerPort is the port number a probe reaches, resolving a named
// port against the container that declares it.
func probedContainerPort(c *corev1.Container, port intstr.IntOrString) (int32, error) {
	if port.Type == intstr.Int {
		return port.IntVal, nil
	}
	for _, declared := range c.Ports {
		if declared.Name == port.StrVal {
			return declared.ContainerPort, nil
		}
	}
	return 0, fmt.Errorf("probe port %q is declared by no port of the container", port.StrVal)
}

// probedPath is the path a probe reaches, which the kubelet defaults to "/".
func probedPath(probePath string) string {
	if probePath == "" {
		return "/"
	}
	return probePath
}

func isMeshPort(port int32) bool {
	return port == workloadclaims.MeshOutboundPort ||
		port == workloadclaims.MeshInboundPort ||
		port == workloadclaims.MeshHealthPort
}

// WorkloadContainers are the pod's own containers, in the order their
// probes are rendered. A platform container's probes are the injector's.
func WorkloadContainers(pod *corev1.Pod) []*corev1.Container {
	var containers []*corev1.Container
	for _, list := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for i := range list {
			if workloadclaims.IsInjectedContainerName(list[i].Name) {
				continue
			}
			containers = append(containers, &list[i])
		}
	}
	return containers
}
