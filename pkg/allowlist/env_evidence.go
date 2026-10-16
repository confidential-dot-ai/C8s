package allowlist

import (
	"fmt"
	"maps"
	"slices"
)

// Why a match env policy rejected a container's environment.
const (
	// EnvEvidenceUnavailable: the node reported no environment at all, because
	// the container had no OCI process args or its CDI edits were deferred.
	// Waiting never recovers it.
	EnvEvidenceUnavailable = "unavailable"
	// EnvEvidenceMissing: the node reported the aggregate digest alone. It had
	// no match policy for the image when it answered, it recorded the
	// container with software that predates per-variable digests, or the
	// environment exceeds the per-variable evidence limits.
	EnvEvidenceMissing = "missing"
	// EnvEvidenceEvicted: the node dropped the per-variable digests to bound
	// the sandbox's inventory.
	EnvEvidenceEvicted = "evicted"
	// EnvEvidenceMismatch: per-variable digests are present and no match
	// policy for the image admits them.
	EnvEvidenceMismatch = "mismatch"
)

// CheckVariableEvidenceBudget rejects a workload whose containers could need
// more per-variable evidence than a node keeps per sandbox: its own containers
// would evict each other's evidence. It charges every container of an image a
// match policy lists, whatever its own env policy, since a node retains their
// evidence at the same priority. Matching does not assign containers to
// declarations, so it charges each declaration the largest evidence any
// declaration it could stand in for admits: same image, overlapping argv. It
// does not charge records of exited containers or of images only another
// workload's match policy lists.
func (w Workload) CheckVariableEvidenceBudget() error {
	containers := w.containers()
	listed := map[string]bool{}
	for _, c := range containers {
		if c.Env.Policy == PolicyMatch {
			listed[c.Digest.String()] = true
		}
	}
	total := 0
	for _, c := range containers {
		if !listed[c.Digest.String()] {
			continue
		}
		charge := 0
		for _, other := range containers {
			if c.argvOverlaps(other) {
				charge = max(charge, other.Env.maxVariableEvidenceBytes())
			}
		}
		total += charge
	}
	if total > MaxSandboxVariableEvidenceBytes {
		return fmt.Errorf("containers of match env images need up to %d bytes of per-variable evidence; a node keeps at most %d per sandbox", total, MaxSandboxVariableEvidenceBytes)
	}
	return nil
}

// argvOverlaps reports whether some container of c's image satisfies both c's
// and o's command and args policies. Each pair of policies admits either one
// argv or every extension of a prefix, so a common argv exists only if one
// side's shortest argv satisfies both.
func (c Container) argvOverlaps(o Container) bool {
	for _, argv := range [][]string{c.shortestArgv(), o.shortestArgv()} {
		r := RunningContainer{Digest: c.Digest.String(), Argv: argv}
		if c.admitsProcess(r) && o.admitsProcess(r) {
			return true
		}
	}
	return false
}

func (c Container) shortestArgv() []string {
	var argv []string
	if c.Command.Policy == PolicyExact {
		argv = c.Command.Argv
	}
	if c.Command.Policy != PolicyDeny && c.Args.Policy == PolicyExact {
		argv = slices.Concat(argv, c.Args.Argv)
	}
	return argv
}

// maxRecordVariableEvidenceBytes bounds one record's serialized
// VariableDigests: JSON escapes a name byte into at most six bytes.
const maxRecordVariableEvidenceBytes = 2 + maxVariableEvidence*(len(`"":,`)+66) + 6*maxVariableEvidenceNameBytes

// maxVariableEvidenceBytes bounds the per-variable evidence a node keeps for
// an environment p admits.
func (p EnvPolicy) maxVariableEvidenceBytes() int {
	switch p.Policy {
	case PolicyMatch:
		return variableEvidenceBytes(maps.Keys(p.Variables))
	case PolicyExact:
		if checkVariableEvidenceLimits(maps.Keys(p.Values)) != nil {
			return 0
		}
		return variableEvidenceBytes(maps.Keys(p.Values))
	case PolicyDeny:
		return variableEvidenceBytes(maps.Keys(map[string]string{}))
	default:
		return maxRecordVariableEvidenceBytes
	}
}

// DiagnoseEnvEvidence names why w's match env policies for r's image reject
// r's environment: one of the EnvEvidence constants. It returns "" when no
// match container admits r's argv and mounts, so the env is not why r is
// rejected, or when one of them admits r outright.
func (w Workload) DiagnoseEnvEvidence(r RunningContainer) string {
	matched := false
	for _, c := range w.containers() {
		if c.Env.Policy != PolicyMatch {
			continue
		}
		if c.admits(r) {
			return ""
		}
		relaxed := c
		relaxed.Env = EnvPolicy{Policy: PolicyAny}
		matched = matched || relaxed.admits(r)
	}
	switch {
	case !matched:
		return ""
	case r.Env == nil:
		return EnvEvidenceUnavailable
	case r.Env.VariableDigestsEvicted:
		return EnvEvidenceEvicted
	case r.Env.VariableDigests == nil:
		return EnvEvidenceMissing
	default:
		return EnvEvidenceMismatch
	}
}
