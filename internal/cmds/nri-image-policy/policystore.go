package nriimagepolicy

import (
	"maps"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// policySnapshot is an immutable admission view: an Index built from the
// last-applied Trust Authority pull, tagged with that pull's version.
// Swapped as a unit; policyStore checks the base allowlist ahead of it.
type policySnapshot struct {
	index *allowlist.Index
	// pulled is the served document the index was built from: a pod's
	// workload match, and so its exits, are read from its entries.
	pulled  *allowlist.Allowlist
	version uint64
	// deadline is the earliest deadline among the component sets this index
	// holds in force; zero when it holds no retiring set. Past it the index
	// no longer stands for the document it was built from.
	deadline time.Time
}

// setEnded reports whether a component set this index holds in force has
// reached its deadline at now.
func (s *policySnapshot) setEnded(now time.Time) bool {
	return !s.deadline.IsZero() && !now.Before(s.deadline)
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
	// clock is the Trust Authority time component-set deadlines are judged by.
	clock *taClock
}

// newPolicyStore seeds the store with an empty snapshot (version 0) so admission
// enforces the base allowlist alone before the first pull lands and after any
// pull failure. A nil base admits nothing.
func newPolicyStore(base *allowlist.Allowlist, clock *taClock) *policyStore {
	if base == nil {
		base = &allowlist.Allowlist{}
	}
	s := &policyStore{
		base:   base.BuildIndex(),
		grants: withoutStaticPods(base).BuildIndex(),
		clock:  clock,
	}
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

// grantsHostBind reports whether the base, less its static-pod entries, or
// snap's allowlist hands r the host bind m (allowlist.Index.GrantsHostBind).
func (s *policyStore) grantsHostBind(snap *policySnapshot, r allowlist.RunningContainer, m allowlist.ObservedMount) bool {
	if s == nil {
		return false
	}
	if s.grants.GrantsHostBind(r, m) {
		return true
	}
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

// grantsHostPorts reports whether the base, less its static-pod entries, or
// snap's allowlist hands r every mapping (allowlist.Index.GrantsHostPorts).
func (s *policyStore) grantsHostPorts(snap *policySnapshot, r allowlist.RunningContainer, mappings []allowlist.HostPort) bool {
	if s == nil {
		return false
	}
	if s.grants.GrantsHostPorts(r, mappings) {
		return true
	}
	return snap != nil && snap.index.GrantsHostPorts(r, mappings)
}

// grantsCapabilities reports whether the base, less its static-pod entries, or
// snap's allowlist hands r every capability in caps
// (allowlist.Index.GrantsCapabilities).
func (s *policyStore) grantsCapabilities(snap *policySnapshot, r allowlist.RunningContainer, caps []string) bool {
	if s == nil {
		return false
	}
	if s.grants.GrantsCapabilities(r, caps) {
		return true
	}
	return snap != nil && snap.index.GrantsCapabilities(r, caps)
}

// declaredCapabilities is every capability the base, less its static-pod
// entries, or snap's allowlist declares for this launch
// (allowlist.Index.DeclaredCapabilities).
func (s *policyStore) declaredCapabilities(snap *policySnapshot, r allowlist.RunningContainer) [][]string {
	if s == nil {
		return nil
	}
	declared := s.grants.DeclaredCapabilities(r)
	if snap != nil {
		declared = append(declared, snap.index.DeclaredCapabilities(r)...)
	}
	return declared
}

// nodeRootBinds returns the mounts a nodeRootFile rule of the base or snap's
// allowlist names for digest (allowlist.Index.NodeRootBinds).
func (s *policyStore) nodeRootBinds(snap *policySnapshot, digest string, mounts []allowlist.ObservedMount) []allowlist.ObservedMount {
	if s == nil {
		return nil
	}
	binds := s.base.NodeRootBinds(digest, mounts)
	if snap != nil {
		binds = append(binds, snap.index.NodeRootBinds(digest, mounts)...)
	}
	return binds
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
// applied one — an epoch rollback a withheld/rolled-back Trust Authority must not use to
// loosen a tightened policy. Reports whether it applied. Single-writer: only the
// pull loop calls it, so the read-compare-store needs no lock against other
// writers.
//
// The applied version is process-local (newPolicyStore starts at 0), so
// rollback is only rejected within a process lifetime: after a restart the first
// pull is trusted, whatever its version, and state re-syncs from the Trust Authority. Surviving a
// restart would need a monotonic counter the host cannot reset — out of scope; on
// the untrusted host a persisted file is itself host-controlled. See
// docs/allowlist-and-capabilities.md.
func (s *policyStore) apply(pulled *allowlist.Allowlist, version uint64) bool {
	if s.rolledBack(version) {
		return false
	}
	s.snap.Store(s.snapshot(pulled, version))
	return true
}

// snapshot is pulled as an admission view at the current Trust Authority time:
// its workloads and the entries of every component set in force.
func (s *policyStore) snapshot(pulled *allowlist.Allowlist, version uint64) *policySnapshot {
	now := s.clock.now()
	deadline, _ := pulled.EarliestDeadline(now)
	return &policySnapshot{
		index:    pulled.BuildIndexAt(now),
		pulled:   pulled,
		version:  version,
		deadline: deadline,
	}
}

// rebuildEndedSets rebuilds the snapshot from the document it was built from
// once a component set it held in force has reached its deadline, and reports
// whether it did. The served bytes and their version are unchanged: the set
// ends because Trust Authority time passed its deadline, not because policy
// was rewritten.
func (s *policyStore) rebuildEndedSets() bool {
	for {
		cur := s.snap.Load()
		if cur == nil || cur.pulled == nil || !cur.setEnded(s.clock.now()) {
			return false
		}
		if s.snap.CompareAndSwap(cur, s.snapshot(cur.pulled, cur.version)) {
			return true
		}
	}
}

// baseBindsRole reports whether the measured base binds this launch a role: a
// component container of a set holds one the base binds nothing.
func (s *policyStore) baseBindsRole(r allowlist.RunningContainer) bool {
	return s.base.RoleOf(r) != ""
}

// roleOf is the platform role the base allowlist, or a component set the
// applied document holds in force, binds to this launch. Two of them binding
// different roles bind none, as two declarations within one index do.
func (s *policyStore) roleOf(r allowlist.RunningContainer) string {
	if s == nil {
		return ""
	}
	served := ""
	if snap := s.current(); snap != nil {
		served = snap.index.RoleOf(r)
	}
	return agreedRole(s.base.RoleOf(r), served)
}

// agreedRole is the role two indexes agree on: the one either binds alone, or
// none when they name different roles.
func agreedRole(base, served string) string {
	switch {
	case base == served || served == "":
		return base
	case base == "":
		return served
	default:
		return ""
	}
}

// bindsRoleMounts reports whether a declaration of the base or of a component
// set in force grants r the role and pins its mount set
// (allowlist.Index.BindsRoleMounts).
func (s *policyStore) bindsRoleMounts(r allowlist.RunningContainer, role string) bool {
	if s == nil {
		return false
	}
	if s.base.BindsRoleMounts(r, role) {
		return true
	}
	snap := s.current()
	return snap != nil && snap.index.BindsRoleMounts(r, role)
}

// raiseAppliedVersion raises the applied version to version, at which Trust Authority
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
