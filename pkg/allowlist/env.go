package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// EnvObservation commits to the complete OCI launch environment. Nil means
// unavailable evidence, never an empty environment. Values are never reported.
type EnvObservation struct {
	Format string `json:"format"`
	Digest string `json:"digest"`
}

const EnvFormat = "c8s.env/v1"

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
	return fingerprintEnv(values), nil
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
	return name != "" && !strings.ContainsAny(name, "=\x00") && !strings.ContainsRune(value, 0) && utf8.ValidString(name) && utf8.ValidString(value)
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

func (o *EnvObservation) Valid() bool {
	if o == nil || o.Format != EnvFormat || len(o.Digest) != 64 {
		return false
	}
	b, err := hex.DecodeString(o.Digest)
	return err == nil && hex.EncodeToString(b) == o.Digest
}

func (o *EnvObservation) Clone() *EnvObservation {
	if o == nil {
		return nil
	}
	c := *o
	return &c
}

func (p EnvPolicy) admitsObservation(o *EnvObservation) bool {
	switch p.Policy {
	case PolicyAny, "":
		return true
	case PolicyDeny:
		return o.Valid() && *o == *fingerprintEnv(nil)
	case PolicyExact:
		return p.Values != nil && o.Valid() && *o == *fingerprintEnv(p.Values)
	default:
		return false
	}
}

// ParseEnvPoliciesJSON reads per-container policies for CLI derivation. Exact
// literals are deliberately supplied by the operator, never fetched from a Pod.
func ParseEnvPoliciesJSON(data []byte) (map[string]EnvPolicy, error) {
	if err := validateJSON(data); err != nil {
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
