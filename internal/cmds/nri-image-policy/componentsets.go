package nriimagepolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

// A pod's component sets are computed where they are needed, from the
// containers the inventory records for its sandbox: the sets in force that
// admit every container a c8s component role was bound to
// (workloadclaims.ComponentSets). Nothing is kept beside the inventory, so a
// restart recovers the membership with the containers.

// admitOnComponentSets refuses a start the component sets in force forbid: the
// pod's recorded component containers and the starting one must run on one set
// in force.
func (p *plugin) admitOnComponentSets(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) error {
	recorded, err := p.recordedContainers(pod.GetId())
	if err != nil {
		// A sandbox that admitted a container with no resolved digest holds no
		// identity; the starting container is judged on its own.
		p.logger.Warn("judging a start against the component sets in force on its own launch",
			"namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "error", err)
		recorded = nil
	}
	launch := p.observedLaunch(ctx, p.observeContainer(pod, ctr, imageRef))
	return p.componentSetRefusal(append(recorded, p.sandboxContainer(launch)))
}

// componentSetRefusal is why the containers of one sandbox may not run on the
// component sets the applied document holds in force at the Trust Authority's
// time, and nil when they may. A pod off its sets is refused every start, its
// tenant containers included, and the component containers of one pod must
// share a set, so no pod mixes two releases' components — a set's beside the
// measured base's included.
func (p *plugin) componentSetRefusal(containers []workloadclaims.SandboxContainer) error {
	snap := p.policy.current()
	if snap == nil || snap.pulled == nil {
		return nil
	}
	now := p.policy.clock.now()
	for _, c := range containers {
		if p.offItsSets(snap.pulled, c, now) {
			return fmt.Errorf("no component set in force admits this pod's component container %s", c.Digest)
		}
	}
	if _, err := workloadclaims.ComponentSets(snap.pulled, containers, now); err != nil {
		return fmt.Errorf("%w: %s", err, setsPerComponent(snap.pulled, containers, now))
	}
	return nil
}

// offItsSets reports whether this container of the pod is a c8s component no
// component set in force admits: it was admitted under a role, or the served
// document declares its launch in a set of its own. The second case carries a
// restart, whose recovered containers take their role from the current index
// and so hold none. A role the measured base binds needs no set: an older
// worker image's components are judged as before.
func (p *plugin) offItsSets(served *allowlist.Allowlist, c workloadclaims.SandboxContainer, now time.Time) bool {
	launch := c.Running()
	if p.policy.baseBindsRole(launch) || len(served.SetsAdmitting(launch, now)) > 0 {
		return false
	}
	return c.Role != "" || len(served.SetsDeclaring(launch)) > 0
}

// setsPerComponent names the sets in force admitting each of the pod's
// component containers, so a refusal says which releases it would mix.
func setsPerComponent(served *allowlist.Allowlist, containers []workloadclaims.SandboxContainer, now time.Time) string {
	var named []string
	for _, c := range containers {
		if c.Role == "" {
			continue
		}
		named = append(named, c.Role+" on "+setVersions(served.SetsAdmitting(c.Running(), now)))
	}
	return strings.Join(named, ", ")
}

// setVersions names sets for a refusal or a log line.
func setVersions(refs []allowlist.SetRef) string {
	if len(refs) == 0 {
		return "no component set"
	}
	versions := make([]string, len(refs))
	for i, ref := range refs {
		versions[i] = ref.Version
	}
	return "component set " + strings.Join(versions, ", ")
}
