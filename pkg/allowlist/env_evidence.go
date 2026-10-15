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

// CheckVariableEvidenceBudget rejects a workload whose match containers could
// need more per-variable evidence than a node keeps per sandbox: its own
// containers would evict each other's evidence.
func (w Workload) CheckVariableEvidenceBudget() error {
	total := 0
	for _, c := range w.containers() {
		if c.Env.Policy == PolicyMatch {
			total += variableEvidenceBytes(maps.Keys(c.Env.Variables))
		}
	}
	if total > MaxSandboxVariableEvidenceBytes {
		return fmt.Errorf("match env policies need %d bytes of per-variable evidence; a node keeps at most %d per sandbox", total, MaxSandboxVariableEvidenceBytes)
	}
	return nil
}

// DiagnoseEnvEvidence names why w's match env policies for r's image reject
// r's environment: one of the EnvEvidence constants. It returns "" when w has
// no match policy for the image or one of them admits the environment.
func (w Workload) DiagnoseEnvEvidence(r RunningContainer) string {
	matched := false
	for _, c := range w.containers() {
		if c.Digest.String() != r.Digest || c.Env.Policy != PolicyMatch {
			continue
		}
		matched = true
		if c.Env.admitsObservation(r.Env) {
			return ""
		}
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
