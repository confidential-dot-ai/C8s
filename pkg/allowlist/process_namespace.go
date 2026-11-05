package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// SharesProcessNamespace reports whether this entry declares a shared group.
func (w Workload) SharesProcessNamespace() bool {
	return slices.ContainsFunc(w.containers(), func(c Container) bool {
		return c.ShareProcessNamespace
	})
}

// SchemaForWorkloads returns the oldest schema that can enforce every entry.
func SchemaForWorkloads(workloads map[string]Workload) string {
	for _, w := range workloads {
		if w.SharesProcessNamespace() {
			return ProcessNamespaceSchema
		}
	}
	return Schema
}

// ProcessNamespacePolicy binds a process-access group to its complete,
// normalized workload policy, including its secret and network grants.
// Informational names do not authorize membership.
func (w Workload) ProcessNamespacePolicy() string {
	data, err := json.Marshal(w)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (w Workload) processNamespaceContainers() []Container {
	containers := w.containers()
	policy := ""
	for i := range containers {
		if containers[i].ShareProcessNamespace {
			if policy == "" {
				policy = w.ProcessNamespacePolicy()
			}
			containers[i].processNamespacePolicy = policy
		}
	}
	return containers
}

// ProcessNamespacePolicies returns the namespace policies that admit the
// complete launch before namespace assignment. Empty string permits a private
// namespace. A caller must reject conflicting policies, never combine them.
// This query grants no permission to start a process or release a secret.
func (i *Index) ProcessNamespacePolicies(r RunningContainer) []string {
	if i == nil {
		return nil
	}
	digest, err := types.ParseDigest(r.Digest)
	if err != nil {
		return nil
	}
	r.Digest = digest.String()
	var policies []string
	for _, c := range i.byDigest[r.Digest] {
		if !c.admitsLaunch(r) {
			continue
		}
		policy := ""
		if c.ShareProcessNamespace {
			policy = c.processNamespacePolicy
		}
		if !slices.Contains(policies, policy) {
			policies = append(policies, policy)
		}
	}
	slices.Sort(policies)
	return policies
}

func (w Workload) validateProcessNamespace() error {
	for _, c := range w.InitContainers {
		if c.ShareProcessNamespace {
			return fmt.Errorf("shareProcessNamespace is permitted only on main application containers")
		}
	}
	shared := false
	for _, c := range w.Containers {
		if !c.ShareProcessNamespace {
			continue
		}
		shared = true
		if c.Role != "" || len(c.Execs) > 0 || w.StaticPod {
			return fmt.Errorf("shareProcessNamespace is not permitted on a platform role, an exec grant, or a static pod")
		}
	}
	if shared && !w.launchPinned() {
		return fmt.Errorf("shareProcessNamespace requires every container to pin command, args, mounts, and environment")
	}
	return nil
}
