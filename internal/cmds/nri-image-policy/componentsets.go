package nriimagepolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// podComponentSets is each sandbox's component-set membership: the component
// sets admitting every c8s component container the pod has run, each judged
// when that container was admitted. A restart rebuilds it from the recovered
// containers (recoverExisting); nothing is persisted.
type podComponentSets struct {
	mu        sync.Mutex
	bySandbox map[string]podSets
}

// podSets is one pod's membership. onASet marks a pod a component set admitted
// a container of, so sets empty beside it means the pod's component containers
// share no set. A pod whose component containers the base alone admits is on
// no set and judged without sets.
type podSets struct {
	sets   []allowlist.SetRef
	onASet bool
}

// joinSet puts a component container admitted by the sets in admitting on its
// pod's membership, which becomes the sets admitting every component container
// of the pod. It reports the refusal when that leaves the pod no set: the
// control plane cannot mix two releases' components in one pod.
func (s *podComponentSets) joinSet(sandboxID string, admitting []allowlist.SetRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bySandbox == nil {
		s.bySandbox = map[string]podSets{}
	}
	held, onRecord := s.bySandbox[sandboxID]
	joined := podSets{onASet: held.onASet || len(admitting) > 0}
	switch {
	case !onRecord:
		joined.sets = slices.Clone(admitting)
	case held.onASet && len(admitting) > 0:
		joined.sets = sharedSets(held.sets, admitting)
	}
	s.bySandbox[sandboxID] = joined
	if joined.onASet && len(joined.sets) == 0 {
		return fmt.Errorf("a container admitted by %s cannot join a pod whose component containers run on %s: one component set must admit every component container of a pod",
			setVersions(admitting), setVersions(held.sets))
	}
	return nil
}

// offSetsInForce reports a pod none of whose sets is among the ones in force,
// with the sets it is on. A pod on no set is never off its sets.
func (s *podComponentSets) offSetsInForce(sandboxID string, inForce []allowlist.SetRef) ([]allowlist.SetRef, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := s.bySandbox[sandboxID]
	if !held.onASet {
		return nil, false
	}
	for _, ref := range held.sets {
		if slices.Contains(inForce, ref) {
			return nil, false
		}
	}
	return held.sets, true
}

func (s *podComponentSets) forget(sandboxID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bySandbox, sandboxID)
}

// sharedSets are the sets both memberships name, by version and digest.
func sharedSets(held, admitting []allowlist.SetRef) []allowlist.SetRef {
	var shared []allowlist.SetRef
	for _, ref := range held {
		if slices.Contains(admitting, ref) {
			shared = append(shared, ref)
		}
	}
	return shared
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

// joinComponentSet puts an admitted component container — one the base or a
// set in force binds a role to — on its pod's component sets, and refuses a
// launch that would leave the pod's component containers on no shared set.
func (p *plugin) joinComponentSet(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) error {
	launch := p.observedLaunch(ctx, p.observeContainer(pod, ctr, imageRef))
	if p.roleOf(launch) == "" {
		return nil
	}
	return p.componentSets.joinSet(pod.GetId(), p.policy.setsAdmitting(launch))
}

// rejoinComponentSet puts a recovered component container back on its pod's
// sets, so a restart recomputes membership from what runs. A pod the recovered
// containers leave on no set in force ends (endPodsOnEndedSets), and its
// containers are refused at admission whatever happens here.
func (p *plugin) rejoinComponentSet(sandboxID string, launch allowlist.RunningContainer, role string) {
	if role == "" {
		return
	}
	if err := p.componentSets.joinSet(sandboxID, p.policy.setsAdmitting(launch)); err != nil {
		p.logger.Warn("a recovered pod's component containers share no component set",
			"sandbox", sandboxID, "error", err)
	}
}
