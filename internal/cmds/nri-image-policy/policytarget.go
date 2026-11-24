package nriimagepolicy

import (
	"context"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// policyTarget puts a pulled allowlist into force.
type policyTarget interface {
	// policy is the store admission reads, whose applied version later
	// pulls must not go below.
	policy() *policyStore
	// install puts the startup pull into force.
	install(ctx context.Context, pulled *allowlist.Allowlist, version uint64) error
	// replace puts a later pull into force and stops the running containers
	// it no longer admits.
	replace(ctx context.Context, pulled *allowlist.Allowlist, version uint64) error
	// endSets puts the end of a retired component set into force: the sets a
	// kept document holds are the ones in force at the Trust Authority's time.
	endSets(ctx context.Context)
}

func policyTargetFor(cfg *config, plugin *plugin) policyTarget {
	if cfg.podRole() {
		return podTarget{plugin: plugin}
	}
	return nodeTarget{store: plugin.policy, recheckRunning: plugin.recheckRunning}
}

// nodeTarget is the node's admission index. Its startup install leaves the
// running containers to the plugin's deferred startup check.
type nodeTarget struct {
	store *policyStore
	// recheckRunning ends the pods whose component sets have ended and kills
	// the single containers the policy no longer admits.
	recheckRunning func(context.Context)
}

func (n nodeTarget) policy() *policyStore {
	return n.store
}

func (n nodeTarget) install(
	_ context.Context,
	pulled *allowlist.Allowlist,
	version uint64,
) error {
	n.store.apply(pulled, version)
	return nil
}

func (n nodeTarget) replace(
	ctx context.Context,
	pulled *allowlist.Allowlist,
	version uint64,
) error {
	n.store.apply(pulled, version)
	n.recheckRunning(ctx)
	return nil
}

func (n nodeTarget) endSets(ctx context.Context) {
	if n.store.rebuildEndedSets() {
		n.recheckRunning(ctx)
	}
}

// podTarget is a Pod guest's policy, which applyPodPolicy installs under
// admission's lock.
type podTarget struct {
	plugin *plugin
}

func (p podTarget) policy() *policyStore {
	return p.plugin.policy
}

func (p podTarget) install(
	ctx context.Context,
	pulled *allowlist.Allowlist,
	version uint64,
) error {
	return p.plugin.applyPodPolicy(ctx, pulled, version)
}

func (p podTarget) replace(
	ctx context.Context,
	pulled *allowlist.Allowlist,
	version uint64,
) error {
	return p.plugin.applyPodPolicy(ctx, pulled, version)
}

func (p podTarget) endSets(ctx context.Context) {
	p.plugin.endPodSets(ctx)
}
