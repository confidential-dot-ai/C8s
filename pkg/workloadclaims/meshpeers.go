package workloadclaims

import (
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/workloadname"
)

// MeshPeerWorkloadsEnv is a workload's outbound mesh requirement. The node
// requires its endpoint to carry the same value before that workload starts.
const MeshPeerWorkloadsEnv = "C8S_MESH_PEER_WORKLOADS"

// ParseMeshPeerWorkloads reads canonical comma-separated workload names.
// An empty value leaves outbound authorization at mesh membership.
func ParseMeshPeerWorkloads(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	names := strings.Split(value, ",")
	if len(names) > 32 {
		return nil, fmt.Errorf("%s permits at most 32 names", MeshPeerWorkloadsEnv)
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !workloadname.Valid(name) || seen[name] {
			return nil, fmt.Errorf("%s: invalid or duplicate workload name %q", MeshPeerWorkloadsEnv, name)
		}
		seen[name] = true
	}
	return names, nil
}

// MeshPeerWorkloads reads the final OCI environment, rejecting ambiguous values.
func MeshPeerWorkloads(env []string) (string, error) {
	value, found := "", false
	for _, item := range env {
		name, raw, _ := strings.Cut(item, "=")
		if name != MeshPeerWorkloadsEnv {
			continue
		}
		if found {
			return "", fmt.Errorf("duplicate %s", MeshPeerWorkloadsEnv)
		}
		value, found = raw, true
	}
	_, err := ParseMeshPeerWorkloads(value)
	return value, err
}
