package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/containerd/nri/pkg/api"

	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Host ports are the one host privilege the measured base does not excuse, and
// port-mapping evidence this cannot read refuses the pod whatever the sandbox
// policy mode. See docs/allowlist-and-capabilities.md.

// errRecordGone is a containerd record the node no longer has; a rule that
// reads it decides nothing.
var errRecordGone = errors.New("containerd no longer has the record")

// hostPortRule names the rule in a refusal's log and audit record.
const hostPortRule = "host_port"

// admitSandboxHostPorts refuses a sandbox whose host ports no entry declares;
// containerd takes a refused sandbox's port mappings down with it.
func (p *plugin) admitSandboxHostPorts(ctx context.Context, cfg *config, pod *api.PodSandbox) error {
	if !cfg.sandboxObserved() {
		return nil
	}
	subject := sandboxSubject(hostPortRule, pod)
	mappings, err := p.sandboxHostPorts(ctx, pod)
	if err != nil {
		return p.refuseSandbox(cfg, subject, err)
	}
	if len(mappings) == 0 || p.policy.declaresHostPorts(mappings) {
		return nil
	}
	refusal := fmt.Errorf("the sandbox maps host ports no allowlist entry declares: %s", namedMappings(mappings))
	if cfg.sandboxMode() == SandboxAudit {
		p.auditPrivilege(subject, refusal)
		return nil
	}
	return p.refuseSandbox(cfg, subject, refusal)
}

// refuseSandbox records a sandbox refusal and returns it, or nil under audit mode.
func (p *plugin) refuseSandbox(cfg *config, subject privilegeSubject, refusal error) error {
	p.denyPrivilege(subject, refusal)
	if cfg.Policy.Mode == ModeAudit {
		return nil
	}
	return refusal
}

// hostPortRefusal is why a container of a pod that maps host ports may not run,
// "" when it may; the caller downgrades a denial under audit mode.
func (p *plugin) hostPortRefusal(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef string, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) string {
	subject := containerSubject(hostPortRule, pod, ctr, imageRef)
	mappings, err := p.sandboxHostPorts(ctx, pod)
	switch {
	// A sandbox containerd no longer has runs no container to refuse.
	case errors.Is(err, errRecordGone):
		return ""
	case err != nil:
		p.denyPrivilege(subject, err)
		return err.Error()
	}
	if len(mappings) == 0 {
		return ""
	}
	launch := p.observedLaunch(ctx, ctr, imageRef, env, mounts)
	if platformClientRole(p.roleOf(launch)) || p.policy.grantsHostPorts(launch, mappings) {
		return ""
	}
	refusal := fmt.Errorf("the pod maps host ports %s, which no allowlist entry declares for this launch", namedMappings(mappings))
	if cfg.sandboxMode() == SandboxAudit {
		p.auditPrivilege(subject, refusal)
		return ""
	}
	p.denyPrivilege(subject, refusal)
	return refusal.Error()
}

// platformClientRole reports whether role is one the node injects into a member
// pod (internal/secrets.WorkloadContainers).
func platformClientRole(role string) bool {
	return role == meshRole || role == CredentialRole
}

// sandboxHostPorts is what containerd recorded of the pod's port mappings, as an
// entry declares them. A pod on the node's network maps none of its own.
func (p *plugin) sandboxHostPorts(ctx context.Context, pod *api.PodSandbox) ([]allowlist.HostPort, error) {
	if nodeNetwork(pod) {
		return nil, nil
	}
	network, err := p.containerd.SandboxNetwork(ctx, pod.GetId(), ctrdresolver.SandboxPod{
		Name: pod.GetName(), Namespace: pod.GetNamespace(), UID: pod.GetUid(),
	})
	switch {
	case errdefs.IsNotFound(err):
		return nil, fmt.Errorf("containerd has no sandbox %s: %w", pod.GetId(), errRecordGone)
	case err != nil:
		return nil, fmt.Errorf("cannot read the sandbox's recorded host ports: %w", err)
	}
	if network.HostNetwork {
		return nil, fmt.Errorf("containerd records sandbox %s on the node's network, NRI shows it on its own", pod.GetId())
	}
	return declaredMappings(network.HostPorts)
}

// declaredMappings converts recorded mappings to the form an entry declares
// them in. A mapping bound to one node address is one no entry can declare.
func declaredMappings(recorded []ctrdresolver.HostPort) ([]allowlist.HostPort, error) {
	mappings := make([]allowlist.HostPort, 0, len(recorded))
	for _, m := range recorded {
		if m.HostIP.IsValid() {
			return nil, fmt.Errorf("host port %s %d is mapped on %s alone, which no entry declares", m.Protocol, m.HostPort, m.HostIP)
		}
		protocol, err := declaredProtocol(m.Protocol)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, allowlist.HostPort{
			Protocol:      protocol,
			HostPort:      int(m.HostPort),
			ContainerPort: int(m.ContainerPort),
		})
	}
	return mappings, nil
}

// declaredProtocol is the spelling an entry declares a recorded protocol in
// (docs/allowlist-entries.md, hostPorts).
func declaredProtocol(recorded ctrdresolver.Protocol) (string, error) {
	switch recorded {
	case ctrdresolver.ProtocolTCP:
		return "TCP", nil
	case ctrdresolver.ProtocolUDP:
		return "UDP", nil
	case ctrdresolver.ProtocolSCTP:
		return "SCTP", nil
	}
	return "", fmt.Errorf("protocol %q is not one an allowlist entry declares", recorded)
}

// namedMappings renders mappings as <protocol> <host port>-><container port>.
func namedMappings(mappings []allowlist.HostPort) string {
	out := make([]string, 0, len(mappings))
	for _, m := range mappings {
		out = append(out, fmt.Sprintf("%s %d->%d", m.Protocol, m.HostPort, m.ContainerPort))
	}
	return strings.Join(out, ", ")
}
