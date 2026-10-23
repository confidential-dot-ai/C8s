package nriimagepolicy

import (
	"context"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// bindExits runs before a container of a member pod starts. It reads the
// allowlist entry the pod's workload containers match with this one running,
// by the rule secret release uses, and hands it to the mesh gate, which
// grants that entry's exits or holds the pod to the entry it granted them
// for. A platform client role changes no match, so it is not weighed.
func (p *plugin) bindExits(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) error {
	if !p.mesh.hosts(pod) {
		return nil
	}
	launch := p.observedLaunch(ctx, ctr, imageRef, containerEnv(ctr), p.observedMounts(pod, ctr))
	starting := workloadclaims.SandboxContainer{
		Digest: launch.Digest,
		Argv:   launch.Argv,
		Env:    launch.Env,
		Mounts: launch.Mounts,
		Role:   p.roleOf(launch),
	}
	if len(secrets.WorkloadContainers([]workloadclaims.SandboxContainer{starting})) == 0 {
		return nil
	}
	entry, exits := p.matchedExits(pod.GetId(), starting)
	return p.mesh.bindEntry(pod, entry, exits)
}

// matchedExits is the one entry the sandbox's workload containers match with
// starting added, and its exits; "" when the inventory cannot answer or no
// single entry of the served allowlist matches.
func (p *plugin) matchedExits(sandboxID string, starting workloadclaims.SandboxContainer) (string, []exit) {
	snap := p.policy.current()
	if p.inventory == nil || snap == nil || snap.pulled == nil {
		return "", nil
	}
	_, reported, known, err := p.inventory.DigestsForSandbox(sandboxID)
	if err != nil || !known {
		return "", nil
	}
	running := secrets.WorkloadContainers(append(reported, starting))
	name, entry, err := snap.pulled.MatchWorkload(running)
	if err != nil {
		return "", nil
	}
	exits := make([]exit, 0, len(entry.Egress))
	for _, e := range entry.Egress {
		exits = append(exits, exit{Range: e.CIDR, Port: e.Port})
	}
	return name, exits
}
