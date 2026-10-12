package webhook

import (
	"fmt"
	"path"
	"regexp"
	"slices"

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

// renderableProbePath holds the characters a rendered probe path carries
// verbatim between the kubelet, the endpoint's mux and the application. Anything
// else — a query, an escape, a space — would reach the endpoint as a path it
// answers for no target.
var renderableProbePath = regexp.MustCompile(`^(/[A-Za-z0-9\-._~]*)+$`)

// rewriteWorkloadProbes moves every HTTP probe of the pod's own containers onto
// the endpoint's health port and returns the targets it rendered, in the order
// the endpoint is given them.
func rewriteWorkloadProbes(pod *corev1.Pod) []string {
	var rendered []string
	for _, c := range workloadProbeContainers(pod) {
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

// rejectUnforwardableProbes refuses a member pod carrying an HTTP probe the
// injector cannot move onto the health port, rather than admitting a pod whose
// probe can never pass.
func rejectUnforwardableProbes(pod *corev1.Pod) error {
	for _, c := range workloadProbeContainers(pod) {
		for _, probe := range []*corev1.Probe{c.StartupProbe, c.ReadinessProbe, c.LivenessProbe} {
			if !probesThePod(probe) || renderedProbe(probe.HTTPGet) {
				continue
			}
			if _, err := forwardableProbePort(c, probe.HTTPGet); err != nil {
				return fmt.Errorf("%w: container %q: %v", errInvalidInjectionAnnotation, c.Name, err)
			}
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
		// Refused by rejectUnforwardableProbes, which both webhooks run first.
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
	if !forwardableProbePath(probedPath(get.Path)) {
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

// forwardableProbePath holds that the rendered path is the path the endpoint
// answers on: an unclean one is redirected by its mux before any target is
// matched.
func forwardableProbePath(probePath string) bool {
	cleaned := path.Clean(probePath)
	if cleaned != probePath && cleaned+"/" != probePath {
		return false
	}
	return renderableProbePath.MatchString(probePath)
}

func isMeshPort(port int32) bool {
	return port == workloadclaims.MeshOutboundPort ||
		port == workloadclaims.MeshInboundPort ||
		port == workloadclaims.MeshHealthPort
}

// workloadProbeContainers are the pod's own containers, in the order their
// probes are rendered. A platform container's probes are the injector's.
func workloadProbeContainers(pod *corev1.Pod) []*corev1.Container {
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
