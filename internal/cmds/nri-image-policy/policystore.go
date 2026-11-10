package nriimagepolicy

import (
	"maps"
	"sync/atomic"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// policySnapshot is an immutable admission view: an Index built from the
// last-applied CDS pull, tagged with that pull's version.
// Swapped as a unit; policyStore checks the base allowlist ahead of it.
type policySnapshot struct {
	index *allowlist.Index
	// pulled is the served document the index was built from: a pod's
	// workload match, and so its exits, are read from its entries.
	pulled  *allowlist.Allowlist
	version uint64
}

// policyStore holds the current admission snapshot. A single writer (the pull
// loop) swaps it via apply; CreateContainer reads it concurrently via current.
// The base allowlist is checked ahead of every snapshot, so a failed or
// withheld pull never drops it.
type policyStore struct {
	base *allowlist.Index // the boot-time base allowlist document
	// grants is base without its static-pod entries, which grant no host
	// bind, host port or capability: the node TCB excuses a static pod
	// (nodeTCBExempt).
	grants *allowlist.Index
	snap   atomic.Pointer[policySnapshot]
}

// newPolicyStore seeds the store with an empty snapshot (version 0) so admission
// enforces the base allowlist alone before the first pull lands and after any
// pull failure. A nil base admits nothing.
func newPolicyStore(base *allowlist.Allowlist) *policyStore {
	if base == nil {
		base = &allowlist.Allowlist{}
	}
	s := &policyStore{base: base.BuildIndex(), grants: withoutStaticPods(base).BuildIndex()}
	s.snap.Store(&policySnapshot{index: (&allowlist.Allowlist{}).BuildIndex()})
	return s
}

// withoutStaticPods is a without its allowlist.Workload.StaticPod entries.
func withoutStaticPods(a *allowlist.Allowlist) *allowlist.Allowlist {
	out := *a
	out.Workloads = maps.Clone(a.Workloads)
	maps.DeleteFunc(out.Workloads, func(_ string, w allowlist.Workload) bool { return w.StaticPod })
	return &out
}

func (s *policyStore) current() *policySnapshot {
	if s == nil {
		return nil
	}
	return s.snap.Load()
}

// baseAdmits applies the same launch phases as the served allowlist: argv at
// preliminary admission, then all constraints once runtime evidence is available.
func (s *policyStore) baseAdmits(r allowlist.RunningContainer, phase launchPhase) bool {
	if s == nil {
		return false
	}
	if phase == launchPreliminary {
		return s.base.AdmitsProcess(r)
	}
	return s.base.AdmitsContainer(r)
}

// admits applies the launch phases of baseAdmits to the served entries.
func (s *policySnapshot) admits(r allowlist.RunningContainer, phase launchPhase) bool {
	if phase == launchPreliminary {
		return s.index.AdmitsProcess(r)
	}
	return s.index.AdmitsContainer(r)
}

// baseAdmitsPinned is the final baseAdmits restricted to entries that pin the
// launch (allowlist.Container.LaunchPinned).
func (s *policyStore) baseAdmitsPinned(r allowlist.RunningContainer) bool {
	if s == nil {
		return false
	}
	return s.base.AdmitsContainerWhere(r, allowlist.Container.LaunchPinned)
}

// grantsHostBind reports whether the base, less its static-pod entries, or the
// applied allowlist hands r the host bind m (allowlist.Index.GrantsHostBind).
func (s *policyStore) grantsHostBind(r allowlist.RunningContainer, m allowlist.ObservedMount) bool {
	if s == nil {
		return false
	}
	if s.grants.GrantsHostBind(r, m) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.GrantsHostBind(r, m)
}

// declaresHostPorts reports whether an entry of the base, less its static-pod
// entries, or the applied allowlist declares every mapping
// (allowlist.Index.DeclaresHostPorts).
func (s *policyStore) declaresHostPorts(mappings []allowlist.HostPort) bool {
	if s == nil {
		return false
	}
	if s.grants.DeclaresHostPorts(mappings) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.DeclaresHostPorts(mappings)
}

// grantsHostPorts reports whether the base, less its static-pod entries, or the
// applied allowlist hands r every mapping (allowlist.Index.GrantsHostPorts).
func (s *policyStore) grantsHostPorts(r allowlist.RunningContainer, mappings []allowlist.HostPort) bool {
	if s == nil {
		return false
	}
	if s.grants.GrantsHostPorts(r, mappings) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.GrantsHostPorts(r, mappings)
}

// grantsCapabilities reports whether the base, less its static-pod entries, or
// the applied allowlist hands r every capability in caps
// (allowlist.Index.GrantsCapabilities).
func (s *policyStore) grantsCapabilities(r allowlist.RunningContainer, caps []string) bool {
	if s == nil {
		return false
	}
	if s.grants.GrantsCapabilities(r, caps) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.GrantsCapabilities(r, caps)
}

// declaredCapabilities is every capability the base, less its static-pod
// entries, or the applied allowlist declares for this launch
// (allowlist.Index.DeclaredCapabilities).
func (s *policyStore) declaredCapabilities(r allowlist.RunningContainer) [][]string {
	if s == nil {
		return nil
	}
	declared := s.grants.DeclaredCapabilities(r)
	if snap := s.current(); snap != nil {
		declared = append(declared, snap.index.DeclaredCapabilities(r)...)
	}
	return declared
}

// declaresNodeRoot reports whether the base or applied allowlist has a
// nodeRootFile rule for digest.
func (s *policyStore) declaresNodeRoot(digest string) bool {
	if s == nil {
		return false
	}
	if s.base.DeclaresNodeRoot(digest) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.DeclaresNodeRoot(digest)
}

// needsVariableEvidence reports whether the base or applied allowlist has a
// match env policy for digest.
func (s *policyStore) needsVariableEvidence(digest string) bool {
	if s == nil {
		return false
	}
	if s.base.NeedsVariableEvidence(digest) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.NeedsVariableEvidence(digest)
}

// apply installs the pulled document at version, unless version is below the
// applied one — an epoch rollback a withheld/rolled-back CDS must not use to
// loosen a tightened policy. Reports whether it applied. Single-writer: only the
// pull loop calls it, so the read-compare-store needs no lock against other
// writers.
//
// The applied version is process-local (newPolicyStore starts at 0), so
// rollback is only rejected within a process lifetime: after a restart the first
// pull is trusted, whatever its version, and state re-syncs from CDS. Surviving a
// restart would need a monotonic counter the host cannot reset — out of scope; on
// the untrusted host a persisted file is itself host-controlled. See
// docs/allowlist-and-capabilities.md.
func (s *policyStore) apply(pulled *allowlist.Allowlist, version uint64) bool {
	if s.rolledBack(version) {
		return false
	}
	s.snap.Store(&policySnapshot{index: pulled.BuildIndex(), pulled: pulled, version: version})
	return true
}

// raiseAppliedVersion raises the applied version to version, at which CDS
// still serves the document the last pull named: a write that moved the
// version and kept the bytes raises the version later pulls are judged
// against. It never lowers it.
func (s *policyStore) raiseAppliedVersion(version uint64) {
	for {
		cur := s.snap.Load()
		if version <= cur.version {
			return
		}
		next := *cur
		next.version = version
		if s.snap.CompareAndSwap(cur, &next) {
			return
		}
	}
}

// rolledBack reports whether version is below the applied one.
func (s *policyStore) rolledBack(version uint64) bool {
	cur := s.snap.Load()
	return cur != nil && version < cur.version
}
