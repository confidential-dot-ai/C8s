package nriimagepolicy

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const pullStallAfter = 5 * time.Minute

type allowlistPull struct {
	cds    string
	now    func() time.Time
	logger *slog.Logger

	mu            sync.Mutex
	waitingSince  time.Time
	failure       error
	stallReported bool
}

func newAllowlistPull(cds string, now func() time.Time, logger *slog.Logger) *allowlistPull {
	return &allowlistPull{
		cds:          cds,
		now:          now,
		waitingSince: now(),
		logger:       logger,
	}
}

func stallMessage(cds string, waited time.Duration, failure error) string {
	if waited < pullStallAfter || failure == nil {
		return ""
	}
	return fmt.Sprintf("no allowlist from %s for %s: %v", cds, waited.Round(time.Second), failure)
}

func (p *allowlistPull) reached() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.waitingSince = p.now()
	p.failure = nil
	p.stallReported = false
}

func (p *allowlistPull) failed(err error) {
	if stall := p.recordFailure(err); stall != "" {
		p.logger.Error("this node admits containers from its baked allowlist: the operator's allowlist has not reached it", "stall", stall)
	}
}

func (p *allowlistPull) recordFailure(err error) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failure = err
	stall := stallMessage(p.cds, p.now().Sub(p.waitingSince), err)
	if stall == "" || p.stallReported {
		return ""
	}
	p.stallReported = true
	return stall
}

func (p *allowlistPull) stall() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return stallMessage(p.cds, p.now().Sub(p.waitingSince), p.failure)
}
