package allowlist

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
)

// ParseMountPoliciesJSON reads a map of container names to explicit mount policies.
func ParseMountPoliciesJSON(data []byte) (map[string]MountPolicy, error) {
	var policies map[string]MountPolicy
	if err := strictjson.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("invalid mount policy file: %w", err)
	}
	for name, p := range policies {
		if p.Policy == "" {
			return nil, fmt.Errorf("container %q requires an explicit mount policy", name)
		}
		if err := normalizeMounts(&p); err != nil {
			return nil, fmt.Errorf("container %q: %w", name, err)
		}
		policies[name] = p
	}
	return policies, nil
}
