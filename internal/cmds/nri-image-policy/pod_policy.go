package nriimagepolicy

import (
	"context"
	"errors"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// applyPodPolicy installs a pulled policy on a Pod guest under admission's
// lock: a credential issuance obtained under the previous policy cannot publish
// under the new one, even if every current container remains admitted.
func (p *plugin) applyPodPolicy(ctx context.Context, pulled *allowlist.Allowlist, version uint64) error {
	p.podMu.Lock()
	defer p.podMu.Unlock()
	if pulled == nil {
		return errors.New("pod policy update is missing its document")
	}
	if !p.podRegistered.Load() {
		return errors.New("pod policy is waiting for verified runtime registration")
	}
	current := p.policy.current()
	if version < current.version {
		return errors.New("pod policy update rolls back the applied version")
	}
	if current.pulled != nil && current.version == version {
		return nil
	}
	p.policy.apply(pulled, version)
	p.inventory.mu.Lock()
	p.inventory.revision++
	p.inventory.mu.Unlock()
	p.podChanged()
	p.KillRevoked(ctx)
	return nil
}
