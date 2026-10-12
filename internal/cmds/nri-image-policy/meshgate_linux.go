//go:build linux

package nriimagepolicy

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
)

// meshSupported gates a mesh policy at config load: a pod ruleset is nftables
// in a Linux network namespace.
const meshSupported = true

// installPodRuleset puts the ruleset trusted policy defines into the namespace
// the enforcer proved.
func installPodRuleset(netns podNamespace, policy meshPolicy) error {
	return ruleset.Install(netns.path, policy.podRuleset())
}

// verifyPodRuleset requires the live ruleset of that same namespace to be the
// one trusted policy defines. A path the runtime re-pointed names another
// namespace, whose rules say nothing about this pod.
func verifyPodRuleset(netns podNamespace, policy meshPolicy) error {
	current, err := namespaceFile(netns.path)
	if err != nil {
		return err
	}
	if current.id != netns.id {
		return fmt.Errorf("the network namespace at %s was replaced", netns.path)
	}
	return ruleset.Verify(netns.path, policy.podRuleset())
}

// podRuleset is the ruleset every member pod on this node carries: the mesh
// endpoint's reserved UID owns the capture ports, and every other role reaches
// only what its binding names.
func (p meshPolicy) podRuleset() ruleset.Policy {
	pod := ruleset.Policy{
		Resolver: p.Resolver,
		Capture:  ruleset.CapturePorts(p.Capture),
	}
	for _, role := range p.Roles {
		if role.Name == meshRole {
			pod.MeshUID = role.UID
			continue
		}
		bound := ruleset.Role{UID: role.UID}
		for _, dst := range role.Destinations {
			bound.Destinations = append(bound.Destinations, ruleset.Destination{
				Addr: dst.Addr(),
				Port: dst.Port(),
			})
		}
		pod.Roles = append(pod.Roles, bound)
	}
	return pod
}
