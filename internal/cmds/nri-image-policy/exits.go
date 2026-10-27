package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// exitDecision is what a pod's workload containers, one more starting among
// them, mean for its exits.
type exitDecision struct {
	// entry is the entry whose exits the pod holds with this container
	// running, and exits those exits; "" for none.
	entry string
	exits []exit
	// refusal keeps the starting container from running.
	refusal error
	// undecided is why the pod's containers could not be read.
	undecided error
	// version is the served allowlist the decision was read from.
	version uint64
	// shadowed are entries with exits never granted to this pod: their launch
	// is not pinned, or the pod completes them and another entry also admits
	// their containers.
	shadowed []string
}

// bindExits runs before a container of a member pod starts, under the pod's
// start lock (meshGate.lockStarts) until that container is on the inventory's
// record. A platform client role changes no match, so it is not weighed.
func (p *plugin) bindExits(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) error {
	if !p.mesh.hosts(pod) {
		return nil
	}
	launch := p.observedLaunch(ctx, ctr, imageRef, containerEnv(ctr), p.observedMounts(pod, ctr))
	starting := p.sandboxContainer(launch)
	if len(secrets.WorkloadContainers([]workloadclaims.SandboxContainer{starting})) == 0 {
		return nil
	}
	return p.mesh.bindEntry(pod, p.exitDecision(pod.GetId(), starting))
}

// sandboxContainer is the workload-match view of a launch the node observed:
// the bytes, arguments and environment, with the role the measured base binds
// to it. It is what secret release and the exit decision match a served
// allowlist against.
func (p *plugin) sandboxContainer(launch allowlist.RunningContainer) workloadclaims.SandboxContainer {
	return workloadclaims.SandboxContainer{
		Digest: launch.Digest,
		Argv:   launch.Argv,
		Env:    launch.Env,
		Mounts: launch.Mounts,
		Role:   p.roleOf(launch),
	}
}

// exitDecision reads the sandbox's workload containers from the inventory,
// as secret release does, adds the starting one, and decides on the node's
// current served allowlist.
func (p *plugin) exitDecision(sandboxID string, starting workloadclaims.SandboxContainer) exitDecision {
	snap := p.policy.current()
	if p.inventory == nil || snap == nil || snap.pulled == nil {
		return exitDecision{undecided: errors.New("no served allowlist or inventory on this node yet")}
	}
	_, reported, known, err := p.inventory.DigestsForSandbox(sandboxID)
	if err != nil {
		return exitDecision{undecided: err, version: snap.version}
	}
	if !known {
		return exitDecision{undecided: fmt.Errorf("the inventory does not know sandbox %s", sandboxID), version: snap.version}
	}
	decision := decideExits(snap.pulled, secrets.WorkloadContainers(append(reported, starting)))
	decision.version = snap.version
	return decision
}

// recoveredExitDecision decides the exits a sandbox already running holds, from
// the launches this enforcer read back from the runtime at connect — not the
// inventory, which the restarted process has not yet repopulated. Every
// container the sandbox runs is in containers, so none is added. A node with no
// served allowlist yet cannot decide: a served allowlist is where egress is
// declared, so until one applies the pod's exits are undecided — recovery then
// grants none and lets the live ruleset decide whether the pod is still a
// member, carrying this cause so a refusal is explained rather than read as
// tampering.
func (p *plugin) recoveredExitDecision(containers []workloadclaims.SandboxContainer) exitDecision {
	snap := p.policy.current()
	if snap == nil || snap.pulled == nil {
		return exitDecision{undecided: errors.New("no served allowlist on this node yet")}
	}
	decision := decideExits(snap.pulled, secrets.WorkloadContainers(containers))
	decision.version = snap.version
	return decision
}

// decideExits decides a pod's exits from its workload containers alone,
// whatever order they started in.
//
// An entry with exits claims a pod once the containers it admits include all
// its main containers and no other entry admits all of them: from then on,
// whatever else starts, the pod can only be that entry. A claimed pod runs
// that entry and nothing else, so a container foreign to it is refused, and
// the pod holds the entry's exits as soon as it is claimed. Containers only
// ever join a pod's record, so a claim, once made, stands, and every start
// order of one set of containers ends in the same outcome: exits granted, a
// container refused, or no exits and no refusal. A claimed set with no
// foreign container is the entry's unique match, so a pod holds exits only
// when it matches their entry by the rule secret release uses.
func decideExits(served *allowlist.Allowlist, running []allowlist.RunningContainer) exitDecision {
	var claims, shadowed []string
	for _, name := range slices.Sorted(maps.Keys(served.Workloads)) {
		entry := served.Workloads[name]
		if len(entry.Egress) == 0 {
			continue
		}
		own := admittedBy(entry, running)
		if len(own) == 0 || len(entry.Diff(own).MissingMains) > 0 {
			continue
		}
		if err := entry.PinnedForEgress(); err != nil {
			// A served document the strict rule did not check: the entry
			// claims nothing and grants nothing.
			shadowed = append(shadowed, fmt.Sprintf("%s (%v)", name, err))
			continue
		}
		if shadow := otherAdmitting(served, name, own); shadow != "" {
			shadowed = append(shadowed, fmt.Sprintf("%s (also admitted by %s)", name, shadow))
			continue
		}
		claims = append(claims, name)
	}
	switch len(claims) {
	case 0:
		return exitDecision{shadowed: shadowed}
	case 1:
	default:
		return exitDecision{refusal: fmt.Errorf("the pod's containers complete allowlist entries %v, which each declare exits; a pod holding exits runs one entry alone", claims)}
	}
	name := claims[0]
	entry := served.Workloads[name]
	if foreign := len(running) - len(admittedBy(entry, running)); foreign > 0 {
		return exitDecision{refusal: fmt.Errorf("the pod runs allowlist entry %q, which declares exits, and %d container(s) that entry does not declare; a pod holding exits runs its entry alone", name, foreign)}
	}
	exits := make([]exit, 0, len(entry.Egress))
	for _, e := range entry.Egress {
		exits = append(exits, exit{Range: e.CIDR, Port: e.Port})
	}
	return exitDecision{entry: name, exits: exits}
}

// admittedBy are the running containers one of entry's declared containers
// admits.
func admittedBy(entry allowlist.Workload, running []allowlist.RunningContainer) []allowlist.RunningContainer {
	var own []allowlist.RunningContainer
	for _, r := range running {
		if len(entry.Diff([]allowlist.RunningContainer{r}).Foreign) == 0 {
			own = append(own, r)
		}
	}
	return own
}

// otherAdmitting names an entry other than name that admits every one of
// containers, "" when none does.
func otherAdmitting(served *allowlist.Allowlist, name string, containers []allowlist.RunningContainer) string {
	for _, other := range slices.Sorted(maps.Keys(served.Workloads)) {
		if other != name && len(served.Workloads[other].Diff(containers).Foreign) == 0 {
			return other
		}
	}
	return ""
}
