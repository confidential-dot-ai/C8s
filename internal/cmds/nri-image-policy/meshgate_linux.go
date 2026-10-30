//go:build linux

package nriimagepolicy

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// installPodRuleset puts the ruleset trusted policy defines for a pod of that
// Kubernetes namespace into the network namespace the enforcer proved.
func installPodRuleset(netns podNamespace, policy meshPolicy, namespace string) error {
	return ruleset.Install(netns.path, policy.podRuleset(namespace, nil))
}

// verifyPodRuleset requires the live ruleset of that same namespace to be the
// one trusted policy defines, with the exits the pod was granted. A path the
// runtime re-pointed names another namespace, whose rules say nothing about
// this pod.
func verifyPodRuleset(netns podNamespace, policy meshPolicy, namespace string, exits []exit) error {
	if err := requireSameNamespace(netns); err != nil {
		return err
	}
	return ruleset.Verify(netns.path, policy.podRuleset(namespace, exits))
}

// extendPodRuleset adds a pod's granted exits to the ruleset it was protected
// with.
func extendPodRuleset(netns podNamespace, policy meshPolicy, namespace string, exits []exit) error {
	if err := requireSameNamespace(netns); err != nil {
		return err
	}
	return ruleset.Extend(netns.path, policy.podRuleset(namespace, nil), rulesetExits(exits))
}

func requireSameNamespace(netns podNamespace) error {
	current, err := namespaceFile(netns.path)
	if err != nil {
		return err
	}
	if current.id != netns.id {
		return fmt.Errorf("the network namespace at %s was replaced", netns.path)
	}
	return nil
}

func rulesetExits(exits []exit) []ruleset.Exit {
	var out []ruleset.Exit
	for _, e := range exits {
		out = append(out, ruleset.Exit{Range: e.Range, Port: e.Port})
	}
	return out
}

// podRuleset is the ruleset a member pod of that Kubernetes namespace
// carries: the mesh endpoint's reserved UID owns the capture ports, every
// dialing role reaches only what its binding names, every container reaches
// the platform services the policy names and the exits the pod was granted,
// and a pod of the router's namespace also answers the router's external
// listeners.
func (p meshPolicy) podRuleset(kubeNamespace string, granted []exit) ruleset.Policy {
	endpoint, _ := p.role(meshRole)
	return ruleset.Policy{
		Resolver:      p.Resolver,
		Capture:       ruleset.CapturePorts(p.Capture),
		MeshUID:       endpoint.UID,
		ClusterRanges: p.ClusterRanges,
		Exits:         slices.Concat(p.serviceExits(), rulesetExits(granted)),
		Server:        p.servedPorts(kubeNamespace),
		Roles:         p.dialingRoles(),
	}
}

// serviceExits are the platform services trusted policy names for every
// member pod, each one address and port: the baked kube-state-metrics
// Service, which serves cluster object metadata in plain HTTP.
func (p meshPolicy) serviceExits() []ruleset.Exit {
	exits := make([]ruleset.Exit, 0, len(p.Exits))
	for _, exit := range p.Exits {
		exits = append(exits, ruleset.Exit{
			Range: netip.PrefixFrom(exit.Addr(), exit.Addr().BitLen()),
			Port:  exit.Port(),
		})
	}
	return exits
}

// servedPorts is the server role the ruleset of a pod of the router's
// namespace carries, and an empty role for a pod of any other namespace. The
// acme role holds the egress ports and the router role never does, so a
// request the router forwards outside the cluster is captured wherever its
// name resolves. Inside it, the upstream role reaches a member itself, as the
// mesh client of the workload its route names.
//
// The upstream role reaches the CDS port the credential role is bound to,
// outside the cluster, and the verifier that weighs that CDS's evidence where
// policy names a port for it: the front door answers from the signed route
// manifest it fetches there, over armTLS it cannot verify without that
// verifier, and the node is what names both.
func (p meshPolicy) servedPorts(kubeNamespace string) ruleset.ServerRole {
	if kubeNamespace != routerNamespace {
		return ruleset.ServerRole{}
	}
	server := ruleset.ServerRole{
		Listeners: routerListeners,
		Egress: ruleset.ServerEgress{
			UID:   workloadclaims.AcmeUID,
			Ports: acmeEgressPorts,
		},
		Upstream:    workloadclaims.UpstreamUID,
		OutsidePort: p.credentialPort(),
	}
	if verifier, named := p.credentialVerifier(); named && server.OutsidePort != 0 {
		server.Services = append(server.Services, verifier)
	}
	return server
}

// credentialVerifier is the attestation-api that weighs a CDS's evidence for
// the pods on this node: this node's own address, on the port policy names.
func (p meshPolicy) credentialVerifier() (ruleset.Destination, bool) {
	if p.CredentialAttestationPort == 0 || !p.nodeAddr.IsValid() {
		return ruleset.Destination{}, false
	}
	return ruleset.Destination{
		Addr: p.nodeAddr,
		Port: p.CredentialAttestationPort,
	}, true
}

// credentialPort is the port this node's CDS serves on, which the credential
// role is bound to (bindCredentialRole). A policy that binds no such role
// leaves the upstream role without it, as it leaves the credential clients
// without it.
func (p meshPolicy) credentialPort() uint16 {
	role, bound := p.role(CredentialRole)
	if !bound {
		return 0
	}
	return role.Port
}

// dialingRoles are the roles the ruleset permits by port: every bound role
// but the mesh endpoint, whose sockets it exempts by UID instead. Each
// reaches its port outside this cluster, and the credential clients also
// reach the verifier that weighs their CDS's evidence, where policy names a
// port for it.
func (p meshPolicy) dialingRoles() []ruleset.Role {
	var roles []ruleset.Role
	for _, role := range p.Roles {
		if role.Name == meshRole {
			continue
		}
		bound := ruleset.Role{UID: role.UID, OutsidePort: role.Port}
		if verifier, named := p.credentialVerifier(); named && role.Name == CredentialRole {
			bound.Destinations = append(bound.Destinations, verifier)
		}
		roles = append(roles, bound)
	}
	return roles
}
