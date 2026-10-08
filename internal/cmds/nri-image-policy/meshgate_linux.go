//go:build linux

package nriimagepolicy

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// meshSupported gates a mesh policy at config load: a pod ruleset is nftables
// in a Linux network namespace.
const meshSupported = true

// installPodRuleset puts the ruleset trusted policy defines for a pod of that
// Kubernetes namespace into the network namespace the enforcer proved.
func installPodRuleset(netns podNamespace, policy meshPolicy, namespace string) error {
	return ruleset.Install(netns.path, policy.podRuleset(namespace))
}

// verifyPodRuleset requires the live ruleset of that same namespace to be the
// one trusted policy defines. A path the runtime re-pointed names another
// namespace, whose rules say nothing about this pod.
func verifyPodRuleset(netns podNamespace, policy meshPolicy, namespace string) error {
	current, err := namespaceFile(netns.path)
	if err != nil {
		return err
	}
	if current.id != netns.id {
		return fmt.Errorf("the network namespace at %s was replaced", netns.path)
	}
	return ruleset.Verify(netns.path, policy.podRuleset(namespace))
}

// podRuleset is the ruleset a member pod of that Kubernetes namespace
// carries: the mesh endpoint's reserved UID owns the capture ports, every
// dialing role reaches only what its binding names, and a pod of the
// router's namespace also answers the router's external listeners.
func (p meshPolicy) podRuleset(kubeNamespace string) ruleset.Policy {
	endpoint, _ := p.role(meshRole)
	return ruleset.Policy{
		Resolver: p.Resolver,
		Capture:  ruleset.CapturePorts(p.Capture),
		MeshUID:  endpoint.UID,
		Server:   p.servedPorts(kubeNamespace),
		Roles:    p.dialingRoles(),
	}
}

// servedPorts is the server role the ruleset of a pod of the router's
// namespace carries, and an empty role for a pod of any other namespace. The
// acme role holds the egress ports and the router role never does, so a
// request the router forwards is captured wherever its name resolves.
func (p meshPolicy) servedPorts(kubeNamespace string) ruleset.ServerRole {
	if kubeNamespace != routerNamespace {
		return ruleset.ServerRole{}
	}
	return ruleset.ServerRole{
		UID:       workloadclaims.RouterUID,
		Listeners: routerListeners,
		Egress: ruleset.ServerEgress{
			UID:   workloadclaims.AcmeUID,
			Ports: acmeEgressPorts,
		},
		ClusterRanges: p.ClusterRanges,
	}
}

// dialingRoles are the roles the ruleset permits by destination: every bound
// role but the mesh endpoint, whose sockets it exempts by UID instead.
func (p meshPolicy) dialingRoles() []ruleset.Role {
	var roles []ruleset.Role
	for _, role := range p.Roles {
		if role.Name == meshRole {
			continue
		}
		bound := ruleset.Role{UID: role.UID}
		for _, dst := range role.Destinations {
			bound.Destinations = append(bound.Destinations, ruleset.Destination{
				Addr: dst.Addr(),
				Port: dst.Port(),
			})
		}
		roles = append(roles, bound)
	}
	return roles
}
