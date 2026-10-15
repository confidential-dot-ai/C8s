package allowlist

import (
	"fmt"
	"maps"
)

// Why a match env policy rejected a container's environment.
const (
	// EnvEvidenceMissing: the node reported no per-variable digests. It had
	// no match policy for the image when it answered, or the environment
	// exceeds the per-variable evidence limits.
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
// evidence at the same priority. It does not charge records of exited
// containers or of images only another workload's match policy lists.
func (w Workload) CheckVariableEvidenceBudget() error {
	listed := map[string]bool{}
	for _, c := range w.containers() {
		if c.Env.Policy == PolicyMatch {
			listed[c.Digest.String()] = true
		}
	}
	total := 0
	for _, c := range w.containers() {
		if listed[c.Digest.String()] {
			total += c.Env.maxVariableEvidenceBytes()
		}
	}
	if total > MaxSandboxVariableEvidenceBytes {
		return fmt.Errorf("containers of match env images need up to %d bytes of per-variable evidence; a node keeps at most %d per sandbox", total, MaxSandboxVariableEvidenceBytes)
	}
	return nil
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
	case r.Env != nil && r.Env.VariableDigestsEvicted:
		return EnvEvidenceEvicted
	case r.Env == nil || r.Env.VariableDigests == nil:
		return EnvEvidenceMissing
	default:
		return EnvEvidenceMismatch
	}
}
