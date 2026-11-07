// The node's privilege floor (docs/node-exec-mode.md) is the authority: the
// webhook lets an author meet it, or read why not, at admission.

package webhook

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const allCapabilities corev1.Capability = "ALL"

// floorDroppedCapabilities are the container runtime's default capabilities
// that no allowlist entry may declare, so a container holding one is refused.
var floorDroppedCapabilities = []corev1.Capability{
	"NET_RAW",
	"SETGID",
	"SETUID",
}

// withPrivilegeFloor sets what the floor requires where sc leaves it unset. The
// kubelet sets no_new_privs only for an explicit allowPrivilegeEscalation: false.
func withPrivilegeFloor(sc *corev1.SecurityContext) *corev1.SecurityContext {
	out := sc.DeepCopy()
	if out == nil {
		out = &corev1.SecurityContext{}
	}
	if out.AllowPrivilegeEscalation == nil {
		out.AllowPrivilegeEscalation = new(false)
	}
	if out.Capabilities == nil {
		out.Capabilities = &corev1.Capabilities{}
	}
	out.Capabilities.Drop = withFloorDrops(out.Capabilities.Drop)
	return out
}

func withFloorDrops(drop []corev1.Capability) []corev1.Capability {
	if namesCapability(drop, allCapabilities) {
		return drop
	}
	for _, name := range floorDroppedCapabilities {
		if !namesCapability(drop, name) {
			drop = append(drop, name)
		}
	}
	return drop
}

func rejectPrivilegesAboveFloor(pod *corev1.Pod) error {
	for _, c := range authorContainers(pod) {
		if err := containerAboveFloor(pod, c); err != nil {
			return err
		}
	}
	return nil
}

func containerAboveFloor(pod *corev1.Pod, c *corev1.Container) error {
	switch {
	case isPrivileged(c):
		return fmt.Errorf("container %q sets privileged: true, and a C8s node refuses a privileged container; remove securityContext.privileged", c.Name)
	case allowsPrivilegeEscalation(c):
		return fmt.Errorf("container %q sets allowPrivilegeEscalation: true, and a C8s node requires no_new_privs; set securityContext.allowPrivilegeEscalation: false", c.Name)
	case runsAsRoot(pod, c):
		return fmt.Errorf("container %q has runAsUser: 0, and a C8s node refuses a container that runs as root; set securityContext.runAsUser to a nonzero uid", c.Name)
	}
	if name := refusedCapabilityAdd(c); name != "" {
		return fmt.Errorf("container %q adds %s in securityContext.capabilities.add, which no C8s allowlist entry may declare; remove it", c.Name, name)
	}
	return nil
}

func isPrivileged(c *corev1.Container) bool {
	return c.SecurityContext != nil &&
		c.SecurityContext.Privileged != nil &&
		*c.SecurityContext.Privileged
}

func allowsPrivilegeEscalation(c *corev1.Container) bool {
	return c.SecurityContext != nil &&
		c.SecurityContext.AllowPrivilegeEscalation != nil &&
		*c.SecurityContext.AllowPrivilegeEscalation
}

func runsAsRoot(pod *corev1.Pod, c *corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
		return *c.SecurityContext.RunAsUser == 0
	}
	return pod.Spec.SecurityContext != nil &&
		pod.Spec.SecurityContext.RunAsUser != nil &&
		*pod.Spec.SecurityContext.RunAsUser == 0
}

func addedCapabilities(c *corev1.Container) []corev1.Capability {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return nil
	}
	return c.SecurityContext.Capabilities.Add
}

func refusedCapabilityAdd(c *corev1.Container) corev1.Capability {
	for _, name := range addedCapabilities(c) {
		if isRefusedCapability(name) {
			return name
		}
	}
	return ""
}

// isRefusedCapability reports ALL, or a capability no entry may declare; the
// runtime upper-cases the names it is given.
func isRefusedCapability(name corev1.Capability) bool {
	upper := strings.ToUpper(string(name))
	return upper == string(allCapabilities) || pkgallowlist.UndeclarableCapability(upper)
}

// namesCapability matches name case-insensitively, as the runtime does.
func namesCapability(list []corev1.Capability, name corev1.Capability) bool {
	for _, listed := range list {
		if strings.EqualFold(string(listed), string(name)) {
			return true
		}
	}
	return false
}
