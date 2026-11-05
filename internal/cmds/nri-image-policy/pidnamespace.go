package nriimagepolicy

import (
	"context"
	"errors"
	"path/filepath"
	"slices"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// invalidPIDPolicy cannot match a signed workload fingerprint.
const invalidPIDPolicy = "unproved-pid-namespace"

func (p *plugin) pidGrantDirectory() string {
	if p.pidGrantDir != "" {
		return p.pidGrantDir
	}
	return PIDNamespaceGrantDir
}

// processNamespacePolicy reads effective namespace evidence, never a pod request.
func (p *plugin) processNamespacePolicy(ctr *api.Container) string {
	var path string
	count := 0
	for _, ns := range ctr.GetLinux().GetNamespaces() {
		if ns.GetType() == pidNamespace {
			count++
			path = ns.GetPath()
		}
	}
	if count > 1 {
		return invalidPIDPolicy
	}
	if path == "" {
		return ""
	}
	dir := p.pidGrantDirectory()
	grant, err := ReadPIDNamespaceGrant(dir, ctr.GetId())
	if err != nil || grant == nil || grant.Policy == "" ||
		CheckPIDNamespaceGrant(dir, ctr.GetId(), ctr.GetPodSandboxId(), grant.PodUID, path) != nil {
		return invalidPIDPolicy
	}
	if ctr.GetPid() != 0 && ctr.GetState() != api.ContainerState_CONTAINER_STOPPED {
		device, inode, err := ProvePIDNamespace(path, ctr.GetPid())
		if err != nil || device != grant.Device || inode != grant.Inode {
			return invalidPIDPolicy
		}
	}
	return grant.Policy
}

func (p *plugin) processNamespacePolicies(launch allowlist.RunningContainer) []string {
	if p.policy == nil {
		return nil
	}
	policies := p.policy.grants.ProcessNamespacePolicies(launch)
	if snap := p.policy.current(); snap != nil {
		policies = append(policies, snap.index.ProcessNamespacePolicies(launch)...)
	}
	slices.Sort(policies)
	return slices.Compact(policies)
}

// shareApplicationNamespace changes only marked, fully admitted applications.
func (p *plugin) shareApplicationNamespace(
	ctx context.Context,
	pod *api.PodSandbox,
	ctr *api.Container,
	adjustment *api.ContainerAdjustment,
) (*api.ContainerAdjustment, error) {
	launch := p.observedLaunch(ctx, ctr, ctr.GetAnnotations()[annotationImageName], containerEnv(ctr), p.observedMounts(pod, ctr))
	launch.ProcessNamespacePolicy = ""
	policies := p.processNamespacePolicies(launch)
	shared := slices.ContainsFunc(policies, func(policy string) bool { return policy != "" })
	if !shared {
		return adjustment, nil
	}
	if len(policies) != 1 {
		return nil, errors.New("the launch has conflicting signed process namespace policies")
	}
	if !p.Ready() || !p.mesh.hosts(pod) || !p.cfg.requiresTrustedMeshEnforcement() ||
		p.roleOf(launch) != "" || workloadclaims.IsInjectedContainerName(ctr.GetName()) {
		return nil, errors.New("only an admitted application of a protected pod may share its process namespace")
	}
	if err := requirePrivatePIDNamespace(ctr); err != nil {
		return nil, err
	}
	dir := p.pidGrantDirectory()
	path, device, inode, err := EnsurePIDNamespace(dir, pod.GetId(), pod.GetPid())
	if err != nil {
		return nil, err
	}
	grant := PIDNamespaceGrant{
		ContainerID: ctr.GetId(), SandboxID: pod.GetId(), PodUID: pod.GetUid(),
		Policy: policies[0], Path: path, Device: device, Inode: inode,
	}
	if err := WritePIDNamespaceGrant(dir, grant); err != nil {
		return nil, err
	}
	if adjustment == nil {
		adjustment = &api.ContainerAdjustment{}
	}
	adjustment.AddOrReplaceNamespace(&api.LinuxNamespace{Type: pidNamespace, Path: path})
	return adjustment, nil
}

// pidGateEvidence returns a proved path only for a currently admitted group.
func (p *plugin) pidGateEvidence(
	pod *api.PodSandbox,
	ctr *api.Container,
	launch allowlist.RunningContainer,
) (string, string) {
	policy := p.processNamespacePolicy(ctr)
	if policy == "" {
		return "", ""
	}
	launch.ProcessNamespacePolicy = ""
	policies := p.processNamespacePolicies(launch)
	if len(policies) != 1 || policies[0] != policy || policy == invalidPIDPolicy ||
		p.roleOf(launch) != "" || workloadclaims.IsInjectedContainerName(ctr.GetName()) {
		return invalidPIDPolicy, ""
	}
	grant, err := ReadPIDNamespaceGrant(p.pidGrantDirectory(), ctr.GetId())
	if err != nil || grant == nil || grant.PodUID != pod.GetUid() || grant.SandboxID != pod.GetId() {
		return invalidPIDPolicy, ""
	}
	return policy, filepath.Join(p.pidGrantDirectory(), "namespaces", pod.GetId())
}

func applyPIDNamespaceAdjustment(
	ctr *api.Container,
	adjust *api.ContainerAdjustment,
) {
	for _, edit := range adjust.GetLinux().GetNamespaces() {
		if edit.GetType() != pidNamespace {
			continue
		}
		if ctr.Linux == nil {
			ctr.Linux = &api.LinuxContainer{}
		}
		found := false
		for i, ns := range ctr.Linux.Namespaces {
			if ns.GetType() == pidNamespace {
				ctr.Linux.Namespaces[i] = edit
				found = true
			}
		}
		if !found {
			ctr.Linux.Namespaces = append(ctr.Linux.Namespaces, edit)
		}
	}
}

func (p *plugin) requireApplicationPIDPolicy(
	ctx context.Context,
	pod *api.PodSandbox,
	ctr *api.Container,
) error {
	if p.processNamespacePolicy(ctr) == "" {
		return nil
	}
	launch := p.observedLaunch(ctx, ctr, ctr.GetAnnotations()[annotationImageName], containerEnv(ctr), p.observedMounts(pod, ctr))
	policy, path := p.pidGateEvidence(pod, ctr, launch)
	if policy == invalidPIDPolicy || path == "" {
		return errors.New("the application process namespace has no current signed authorization")
	}
	p.mesh.mu.Lock()
	defer p.mesh.mu.Unlock()
	state, err := p.mesh.state(pod.GetId())
	if err != nil {
		return err
	}
	if state.pidPolicy != policy {
		return errors.New("the application process namespace belongs to another workload policy")
	}
	return nil
}
