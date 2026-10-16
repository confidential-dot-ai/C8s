package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
)

// EnvObservation commits to the complete OCI launch environment. Nil means
// unavailable evidence, never an empty environment. Values are never reported.
type EnvObservation struct {
	Format string `json:"format"`
	Digest string `json:"digest"`
	// Nil means per-variable evidence is unavailable.
	VariableDigests map[string]string `json:"variableDigests"`
	// VariableDigestsEvicted reports that the node dropped VariableDigests to
	// keep its sandbox under MaxSandboxVariableEvidenceBytes.
	VariableDigestsEvicted bool `json:"variableDigestsEvicted,omitempty"`
}

const EnvFormat = "c8s.env/v1"

// Per-variable evidence rides in every inventory record, whose response CDS
// caps at 1 MiB. Above these bounds VariableDigests is nil, and a match
// policy, which lists every variable, is rejected when authored.
const (
	maxVariableEvidence          = 128
	maxVariableEvidenceNameBytes = 4 << 10
)

// MaxSandboxVariableEvidenceBytes bounds the serialized VariableDigests a node
// keeps per sandbox, half of CDS's 1 MiB inventory response limit. A workload
// whose match policies could need more is rejected when authored.
const MaxSandboxVariableEvidenceBytes = 512 << 10

// VariableEvidenceBytes is the serialized size of o's VariableDigests, zero
// when it has none.
func (o *EnvObservation) VariableEvidenceBytes() int {
	if o == nil || o.VariableDigests == nil {
		return 0
	}
	return variableEvidenceBytes(maps.Keys(o.VariableDigests))
}

// variableEvidenceBytes is exact: every variable digest is 64 hex characters.
func variableEvidenceBytes(names iter.Seq[string]) int {
	placeholder := strings.Repeat("0", 64)
	digests := map[string]string{}
	for name := range names {
		digests[name] = placeholder
	}
	// Marshal cannot fail on a string map.
	b, _ := json.Marshal(digests)
	return len(b)
}

// ObserveEnv validates before canonicalizing: duplicate names and malformed
// entries must not disappear into a map and later satisfy a constrained grant.
// Errors contain no environment names or values.
func ObserveEnv(entries []string) (*EnvObservation, error) {
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !validEnvPair(name, value) {
			return nil, fmt.Errorf("malformed OCI environment")
		}
		if _, exists := values[name]; exists {
			return nil, fmt.Errorf("duplicate OCI environment name")
		}
		values[name] = value
	}
	observation := fingerprintEnv(values)
	if !variableEvidenceFits(values) {
		return observation, nil
	}
	observation.VariableDigests = make(map[string]string, len(values))
	for name, value := range values {
		observation.VariableDigests[name] = fingerprintEnvVariable(name, value)
	}
	return observation, nil
}

func variableEvidenceFits(values map[string]string) bool {
	return checkVariableEvidenceLimits(maps.Keys(values)) == nil
}

func checkVariableEvidenceLimits(names iter.Seq[string]) error {
	count, nameBytes := 0, 0
	for name := range names {
		count++
		nameBytes += len(name)
	}
	if count > maxVariableEvidence {
		return fmt.Errorf("match env lists %d variables; nodes report per-variable evidence for at most %d", count, maxVariableEvidence)
	}
	if nameBytes > maxVariableEvidenceNameBytes {
		return fmt.Errorf("match env names total %d bytes; nodes report per-variable evidence for at most %d", nameBytes, maxVariableEvidenceNameBytes)
	}
	return nil
}

// ObserveLaunchEnv keeps the last value per name, matching runc's launch environment.
func ObserveLaunchEnv(entries []string) (*EnvObservation, error) {
	seen := make(map[string]bool, len(entries))
	out := make([]string, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		name, _, ok := strings.Cut(entries[i], "=")
		if ok {
			if seen[name] {
				continue
			}
			seen[name] = true
		}
		out = append(out, entries[i])
	}
	slices.Reverse(out)
	return ObserveEnv(out)
}

func validEnvPair(name, value string) bool {
	return validEnvName(name) && validEnvValue(value)
}

func validEnvName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "=\x00") && utf8.ValidString(name)
}

func validEnvValue(value string) bool {
	return !strings.ContainsRune(value, 0) && utf8.ValidString(value)
}

// The encoding is the UTF-8 domain string "c8s.env/v1", a NUL, then Go
// encoding/json's compact object (sorted keys, HTML escaping enabled). Empty
// maps encode as {}, never null. Version this encoding if it ever changes.
func fingerprintEnv(values map[string]string) *EnvObservation {
	if values == nil {
		values = map[string]string{}
	}
	b, _ := json.Marshal(values)
	sum := sha256.Sum256(append([]byte(EnvFormat+"\x00"), b...))
	return &EnvObservation{Format: EnvFormat, Digest: hex.EncodeToString(sum[:])}
}

// Each variable digest binds its name and value with NUL framing; neither permits NUL.
func fingerprintEnvVariable(name, value string) string {
	sum := sha256.Sum256([]byte("c8s.env.variable/v1\x00" + name + "\x00" + value))
	return hex.EncodeToString(sum[:])
}

func validEnvDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	b, err := hex.DecodeString(digest)
	return err == nil && hex.EncodeToString(b) == digest
}

// Valid reports whether o is non-nil, in EnvFormat, and carries well-formed
// digests. It says nothing about whether any policy admits o.
func (o *EnvObservation) Valid() bool {
	if o == nil || o.Format != EnvFormat || !validEnvDigest(o.Digest) {
		return false
	}
	for name, digest := range o.VariableDigests {
		if !validEnvName(name) || !validEnvDigest(digest) {
			return false
		}
	}
	return true
}

func (o *EnvObservation) Clone() *EnvObservation {
	if o == nil {
		return nil
	}
	c := *o
	c.VariableDigests = maps.Clone(o.VariableDigests)
	return &c
}

func (p EnvPolicy) admitsObservation(o *EnvObservation) bool {
	behavior, err := p.behavior()
	return err == nil && behavior.admits(o)
}

// ParseEnvPoliciesJSON reads per-container policies for CLI derivation. Exact
// literals are deliberately supplied by the operator, never fetched from a Pod.
func ParseEnvPoliciesJSON(data []byte) (map[string]EnvPolicy, error) {
	if err := strictjson.Validate(data); err != nil {
		return nil, err
	}
	var policies map[string]EnvPolicy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&policies); err != nil {
		return nil, fmt.Errorf("invalid environment policy file")
	}
	for name, p := range policies {
		if p.Policy == "" {
			return nil, fmt.Errorf("container %q requires an explicit env policy", name)
		}
		if err := normalizeEnv(&p); err != nil {
			return nil, fmt.Errorf("container %q: %w", name, err)
		}
		policies[name] = p
	}
	return policies, nil
}
