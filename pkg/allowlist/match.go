package allowlist

import (
	"fmt"
	"slices"
)

// RunningContainer holds the launch characteristics observed by an enforcer.
// Missing Env is unavailable evidence and fails exact/deny policies.
type RunningContainer struct {
	Digest string
	Argv   []string
	// Mounts is nil when evidence is unavailable. A non-nil empty slice proves
	// that the final OCI spec contained no bind mounts.
	Mounts []ObservedMount
	Env    *EnvObservation
}

// ObservedMount is a bind mount classified by the node. Source is diagnostic
// node-local detail and is excluded from workload identity serialization.
// Volume is the pod volume the node read the mount out of, where it is one of
// the pod's own: the name an exact rule binds.
type ObservedMount struct {
	Destination      string       `json:"destination"`
	Source           string       `json:"-"`
	Volume           string       `json:"-"`
	Class            MountClass   `json:"class"`
	Storage          MountStorage `json:"storage"`
	HostSourceDigest string       `json:"hostSourceDigest,omitempty"`
	ReadOnly         bool         `json:"readOnly,omitempty"`
}

// ErrNoMatch reports that no entry describes the running set; ErrAmbiguous that
// more than one does. Both are refusals, but they say different things to an
// operator: the first is a set that matches nothing, the second a pair of
// entries that cannot be told apart.
var (
	ErrNoMatch   = fmt.Errorf("allowlist: no workload entry matches the running containers")
	ErrAmbiguous = fmt.Errorf("allowlist: more than one workload entry matches the running containers")
)

// MatchWorkload resolves a running container set to the single entry that
// describes it.
//
// An entry matches when every running container is one it declares (digest and
// argv), and every main container it declares is running. It is deliberately not
// set equality: a declared init container may have exited, and a declared native
// sidecar keeps running, so demanding the two sets be equal would refuse
// ordinary pods outright. "Nothing foreign, every main present" admits both
// while still refusing a set containing anything the entry does not name.
//
// running must already have had injected-component containers removed — this
// package does not know which images the platform injects.
//
// Argv is matched against the entry's own policies rather than via Index, whose
// admission is a union across every entry listing a digest: an entry pinning an
// exact command guarantees nothing here if another entry widens the same digest.
func (a *Allowlist) MatchWorkload(running []RunningContainer) (string, Workload, error) {
	if len(running) == 0 {
		// A pod always runs at least the container that is asking, so an empty
		// set is no evidence rather than a set that happens to match an entry
		// declaring nothing.
		return "", Workload{}, ErrNoMatch
	}
	var (
		foundName string
		found     Workload
		matches   int
	)
	for name, w := range a.Workloads {
		if !w.describes(running) {
			continue
		}
		matches++
		if matches > 1 {
			return "", Workload{}, ErrAmbiguous
		}
		foundName, found = name, w
	}
	if matches == 0 {
		return "", Workload{}, ErrNoMatch
	}
	return foundName, found, nil
}

// EntryDiff is the distance between an entry and a running set: what is running
// that the entry does not name, and what it declares as a main that nothing
// running satisfies. Both empty means the entry describes the set.
type EntryDiff struct {
	// Foreign is running containers no declared container admits — the ⊆ half.
	Foreign []RunningContainer
	// MissingMains is declared main containers nothing running satisfies — the
	// ⊇ half. An init container is absent from this by design: a declared init
	// may have exited.
	MissingMains []Container
}

// Describes reports whether the entry matches.
func (d EntryDiff) Describes() bool { return len(d.Foreign) == 0 && len(d.MissingMains) == 0 }

// Diff evaluates an entry against a running set without short-circuiting, so a
// near miss can be reported in full.
//
// This is the release decision itself, not a reconstruction of it: describes is
// Diff().Describes(), so a diagnostic built on this cannot disagree with what
// CDS actually did.
func (w Workload) Diff(running []RunningContainer) EntryDiff {
	declared := make([]Container, 0, len(w.Containers)+len(w.InitContainers))
	declared = append(declared, w.Containers...)
	declared = append(declared, w.InitContainers...)

	var d EntryDiff
	for _, r := range running {
		if !admittedBy(declared, r) {
			d.Foreign = append(d.Foreign, r)
		}
	}
	for _, c := range w.Containers {
		if !anyRunning(running, c) {
			d.MissingMains = append(d.MissingMains, c)
		}
	}
	return d
}

// describes reports whether the entry admits everything running and has all its
// main containers present.
func (w Workload) describes(running []RunningContainer) bool {
	return w.Diff(running).Describes()
}

// admittedBy reports whether some declared container permits this running
// container's digest and argv.
func admittedBy(declared []Container, r RunningContainer) bool {
	for _, c := range declared {
		if c.admits(r) {
			return true
		}
	}
	return false
}

// anyRunning reports whether a declared container is satisfied by something
// running.
func anyRunning(running []RunningContainer, c Container) bool {
	return slices.ContainsFunc(running, func(r RunningContainer) bool {
		return c.admits(r)
	})
}

// admits reports whether this declared container permits the running one.
func (c Container) admits(r RunningContainer) bool {
	if c.Digest.String() != r.Digest {
		return false
	}
	for _, constraint := range c.constraints() {
		if !constraint.admits(r) {
			return false
		}
	}
	return true
}

func (c Container) admitsProcess(r RunningContainer) bool {
	if c.Digest.String() != r.Digest {
		return false
	}
	return (processConstraint{command: &c.Command, args: &c.Args}).admits(r)
}

// pinned reports whether the policy states the mount set itself: exact names
// every non-platform mount, and deny and an absent policy admit none.
func (p MountPolicy) pinned() bool {
	return p.Policy != PolicyAny
}

// admits checks classified final mount evidence. Platform mounts are the
// baseline. Exact means equality with the non-platform rules.
func (p MountPolicy) admits(mounts []ObservedMount) bool {
	if p.Policy == PolicyAny {
		return true
	}
	if mounts == nil {
		return false
	}
	if p.Policy == PolicyDeny || p.Policy == "" {
		return !slices.ContainsFunc(mounts, func(m ObservedMount) bool {
			return m.Class != MountPlatform
		})
	}
	if p.Policy != PolicyExact {
		return false
	}
	seen := make(map[string]bool, len(p.Rules))
	for _, mount := range mounts {
		if mount.Class == MountPlatform {
			continue
		}
		if seen[mount.Destination] || !p.admitsMount(mount) {
			return false
		}
		seen[mount.Destination] = true
	}
	return len(seen) == len(p.Rules)
}

func (p MountPolicy) admitsMount(mount ObservedMount) bool {
	i := slices.IndexFunc(p.Rules, func(rule MountRule) bool {
		return rule.Destination == mount.Destination && rule.Kind == mount.Class
	})
	if i < 0 {
		return false
	}
	behavior := p.Rules[i].behavior()
	return behavior != nil && behavior.admits(mount)
}
