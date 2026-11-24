package workloadclaims

import (
	"fmt"
	"slices"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// ComponentSets are the component sets a pod is on: the sets in force at now
// that admit every container the reporting node bound a c8s component role to.
// A pod whose component containers no set in force admits is on no set — an
// older worker image, which the workloads section judges as before.
//
// Mixing is an error: component containers from two sets, or one from a set
// beside one only a node's measured base admits, leave no set describing the
// pod and release and issuance both refuse it.
func ComponentSets(al *allowlist.Allowlist, reported []SandboxContainer, now time.Time) ([]allowlist.SetRef, error) {
	var admitting [][]allowlist.SetRef
	onASet := false
	for _, c := range reported {
		if c.Role == "" {
			continue
		}
		sets := al.SetsAdmitting(c.Running(), now)
		onASet = onASet || len(sets) > 0
		admitting = append(admitting, sets)
	}
	if !onASet {
		return nil, nil
	}
	sets := admitting[0]
	for _, next := range admitting[1:] {
		sets = intersectSets(sets, next)
	}
	if len(sets) == 0 {
		return nil, fmt.Errorf("the component containers are on no common component set in force")
	}
	return sets, nil
}

// RequireAllowlisted is the membership gate the release path applies: every
// container the sandbox runs is listed by an entry in force at now, so a pod
// whose component set has ended gets nothing new.
func RequireAllowlisted(al *allowlist.Allowlist, reported []SandboxContainer, now time.Time) error {
	index := al.BuildIndexAt(now)
	for _, c := range reported {
		if !index.AdmitsDigest(c.Digest) {
			return fmt.Errorf("container image %s is not allowlisted", c.Digest)
		}
	}
	return nil
}

func intersectSets(sets, keep []allowlist.SetRef) []allowlist.SetRef {
	return slices.DeleteFunc(slices.Clone(sets), func(ref allowlist.SetRef) bool {
		return !slices.Contains(keep, ref)
	})
}

// Running is the container as the allowlist matcher judges it.
func (c SandboxContainer) Running() allowlist.RunningContainer {
	return allowlist.RunningContainer{Digest: c.Digest, Argv: c.Argv, Env: c.Env, Mounts: c.Mounts}
}
