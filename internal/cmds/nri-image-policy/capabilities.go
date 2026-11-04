package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/containerd/nri/pkg/api"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A container holds the node's default capability set
// (allowlist.DefaultCapabilities) and what an entry declares for its launch,
// read from the OCI spec containerd stored for it; a spec this cannot read
// refuses the container. See docs/allowlist-and-capabilities.md.

// capabilityRule names the rule in a refusal's log and audit record.
const capabilityRule = "capability"

// capabilityRefusal is why a container may not hold the capabilities its stored
// OCI spec gives it, "" when it may. A pod in a namespace trusted policy exempts
// keeps what the runtime gave it; the caller downgrades a denial under audit mode.
func (p *plugin) capabilityRefusal(ctx context.Context, cfg *config, pod *api.PodSandbox, ctr *api.Container, imageRef, digest string, snap *policySnapshot, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount) string {
	if p.mesh.policy.exempts(pod.GetNamespace()) {
		return ""
	}
	subject := containerSubject(capabilityRule, pod, ctr, imageRef)
	process, err := p.storedProcess(ctx, ctr)
	switch {
	// A container containerd no longer has holds nothing to refuse.
	case errors.Is(err, errRecordGone):
		return ""
	case err != nil:
		p.denyPrivilege(subject, err)
		return err.Error()
	}
	refusal := p.ungrantedCapabilities(ctx, ctr, imageRef, digest, snap, env, mounts, process)
	if refusal == nil {
		return ""
	}
	if cfg.sandboxMode() == SandboxAudit {
		p.auditPrivilege(subject, refusal)
		return ""
	}
	p.denyPrivilege(subject, refusal)
	return refusal.Error()
}

// storedProcess is the process containerd stored for the container. A spec
// describing no process, or naming no capability sets, is refused.
func (p *plugin) storedProcess(ctx context.Context, ctr *api.Container) (*specs.Process, error) {
	spec, err := p.containerd.ContainerSpec(ctx, ctr.GetId())
	switch {
	case errdefs.IsNotFound(err):
		return nil, fmt.Errorf("containerd has no container %s: %w", ctr.GetId(), errRecordGone)
	case err != nil:
		return nil, fmt.Errorf("cannot read the container's stored OCI spec: %w", err)
	case spec.Process == nil:
		return nil, errors.New("the container's stored OCI spec describes no process")
	case spec.Process.Capabilities == nil:
		return nil, errors.New("the container's stored OCI spec names no capability sets")
	}
	return spec.Process, nil
}

// ungrantedCapabilities is why this process may not hold what it holds, nil when
// the default set covers it or an entry declares every capability beyond it.
func (p *plugin) ungrantedCapabilities(ctx context.Context, ctr *api.Container, imageRef, digest string, snap *policySnapshot, env *allowlist.EnvObservation, mounts []allowlist.ObservedMount, process *specs.Process) error {
	held := heldCapabilities(process.Capabilities)
	if role, reserved := p.mesh.policy.roleIdentity(process.User); reserved {
		return roleRefusal(role, held)
	}
	undeclared := undeclaredCapabilities(held)
	if len(undeclared) == 0 {
		return nil
	}
	return p.undeclaredRefusal(snap, p.admittedLaunch(ctx, ctr, imageRef, digest, env, mounts), undeclared)
}

// roleRefusal: a container on a platform role holds no capability, whatever an entry declares.
func roleRefusal(role string, held []string) error {
	if len(held) == 0 {
		return nil
	}
	return fmt.Errorf("a container of the %s role holds capabilities %s", role, strings.Join(held, ", "))
}

// undeclaredRefusal is why no entry hands this launch the capabilities it holds.
func (p *plugin) undeclaredRefusal(snap *policySnapshot, launch allowlist.RunningContainer, undeclared []string) error {
	if p.policy.grantsCapabilities(snap, launch, undeclared) {
		return nil
	}
	return fmt.Errorf("the container holds capabilities %s, which no allowlist entry declares for this launch", strings.Join(undeclared, ", "))
}

// heldCapabilities is every capability the five sets hold, spelled as an entry
// declares them: no CAP_ prefix.
func heldCapabilities(sets *specs.LinuxCapabilities) []string {
	held := slices.Concat(sets.Bounding, sets.Effective, sets.Permitted, sets.Inheritable, sets.Ambient)
	for i, name := range held {
		held[i] = strings.TrimPrefix(name, "CAP_")
	}
	slices.Sort(held)
	return slices.Compact(held)
}

// undeclaredCapabilities names the held capabilities an entry has to declare.
func undeclaredCapabilities(held []string) []string {
	var out []string
	for _, name := range held {
		if !slices.Contains(allowlist.DefaultCapabilities, name) {
			out = append(out, name)
		}
	}
	return out
}
