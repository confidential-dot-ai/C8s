package nriimagepolicy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
)

// freshnessLimitCap is the longest limit a node takes, whatever lifetime Trust Authority
// reports (issuer.MaxLeafTTL).
const freshnessLimitCap = 24 * time.Hour

// freshness is how far this node may be behind the Trust Authority. A poll is fresh when
// its reply names, by ETag, the document admission applies; the limit is the
// certificate lifetime Trust Authority reports, capped. Past the limit no new
// container the served document admits is started, so the host gains nothing
// by cutting a node off, holding a write back, or feeding a node a document it
// refuses.
//
// The limit is counted on the local clock, which no reply moves.
type freshness struct {
	now func() time.Time

	mu         sync.Mutex
	limit      time.Duration
	at         time.Time // local reading of the last fresh poll; zero before the first
	atLastPoll bool
}

func newFreshness(now func() time.Time) *freshness {
	return &freshness{now: now, limit: freshnessLimitCap}
}

// replied takes a poll reply: the lifetime it reports, and whether it names
// the document admission applies. A reply without a lifetime leaves the cap.
func (f *freshness) replied(lifetime time.Duration, fresh bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.limit = freshnessLimitCap
	if lifetime > 0 {
		f.limit = min(lifetime, freshnessLimitCap)
	}
	f.atLastPoll = fresh
	if fresh {
		f.at = f.now()
	}
}

// unanswered takes a poll the Trust Authority did not answer.
func (f *freshness) unanswered() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.atLastPoll = false
}

// behind reports whether the limit has passed without a fresh poll. Before
// the first fresh poll of this process there is no fresh reading, so the
// limit has already passed.
func (f *freshness) behind() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.at.IsZero() || f.now().Sub(f.at) > f.limit
}

// report is what the health endpoint serves: the last poll's freshness and
// the limit in force.
func (f *freshness) report() (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.atLastPoll, f.limit
}

// refuseBehindTheTA is why a container the served document admits may not
// start while this node is past its freshness limit, and nil when it may:
// until a poll lands only the measured base allowlist admits a container, so
// a node cut off from the Trust Authority starts no pod on a document the Trust Authority may have
// replaced. What already runs keeps running, up to its certificates.
func (p *plugin) refuseBehindTheTA(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) error {
	if !p.cfg.PullEnabled() || !p.policy.freshness.behind() {
		return nil
	}
	launch := p.observedLaunch(ctx, p.observeContainer(ctx, pod, ctr, imageRef))
	if p.policy.baseAdmits(launch, launchFinal) || !p.policy.servedAdmits(launch, launchFinal) {
		return nil
	}
	_, limit := p.policy.freshness.report()
	p.logger.Warn("refusing a container of a pod the served allowlist admits: no allowlist of the Trust Authority's within one certificate lifetime",
		"namespace", pod.GetNamespace(),
		"pod", pod.GetName(),
		"container", ctr.GetName(),
		"limit", limit)
	return fmt.Errorf("this node has had no allowlist of the Trust Authority's within %s: only its base allowlist admits a container until a poll lands", limit)
}
