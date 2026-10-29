//go:build linux

package nriimagepolicy

import (
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The ports the router answers on belong to the ruleset of the pods of its
// namespace, and to no other pod: an inbound accept cannot be tied to a
// socket UID.
func TestPodRulesetServesOwnPortsOnlyInTheRouterNamespace(t *testing.T) {
	policy := meshRoles()

	server := policy.podRuleset(routerNamespace, nil).Server
	if server.Upstream != workloadclaims.UpstreamUID {
		t.Fatalf("server upstream uid = %d, want the reserved %d", server.Upstream, workloadclaims.UpstreamUID)
	}
	if !slices.Equal(server.Listeners, routerListeners) || !slices.Equal(server.Egress.Ports, acmeEgressPorts) {
		t.Fatalf("server ports = %+v, want the compiled listeners and egress ports", server)
	}
	// The identity that forwards application traffic holds no egress port, so
	// a forwarded connection outside the cluster is captured, not passed.
	if server.Egress.UID != workloadclaims.AcmeUID {
		t.Fatalf("server egress = %+v, want the reserved %d", server.Egress, workloadclaims.AcmeUID)
	}
	if len(server.ClusterRanges) != 1 {
		t.Fatalf("server cluster ranges = %v, want the measured range", server.ClusterRanges)
	}

	member := policy.podRuleset("default", nil)
	if member.Server.Upstream != 0 {
		t.Fatalf("a pod outside that namespace serves %+v", member.Server)
	}
	if member.MeshUID != testMeshUID {
		t.Fatalf("member mesh uid = %d, want %d", member.MeshUID, testMeshUID)
	}
	uids := make([]uint32, 0, len(member.Roles))
	for _, role := range member.Roles {
		uids = append(uids, role.UID)
	}
	if !slices.Equal(uids, []uint32{testCertUID}) {
		t.Fatalf("member role uids = %v, want the dialing role alone", uids)
	}
}

// The router answers from the signed route manifest it fetches from CDS, so a
// pod of its namespace reaches the one endpoint the credential role is bound
// to and, where policy names a port for it, the verifier that weighs that
// CDS's evidence: the attestation-api on its own node, wherever CDS runs.
func TestPodRulesetGivesTheRouterRoleItsCDSAndThisNodesVerifier(t *testing.T) {
	policy := meshRoles()
	node := netip.MustParseAddr("172.18.0.2")
	policy.nodeAddr = node
	// A CDS outside this cluster: the endpoint the credential role names.
	policy.Roles = append(policy.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort("172.18.0.9:8443")},
	})

	want := []ruleset.Destination{{Addr: netip.MustParseAddr("172.18.0.9"), Port: 8443}}
	server := policy.podRuleset(routerNamespace, nil).Server
	if !slices.Equal(server.Services, want) {
		t.Fatalf("router services = %+v, want the CDS it is bound to alone", server.Services)
	}
	if member := policy.podRuleset("default", nil).Server; len(member.Services) != 0 {
		t.Fatalf("a pod outside that namespace reaches %+v", member.Services)
	}

	// A node whose attestation-api answers over a port, not a socket: the
	// router weighs that CDS's evidence on its own node and nowhere else.
	policy.CredentialAttestationPort = 8400
	want = append(want, ruleset.Destination{Addr: node, Port: 8400})
	if got := policy.podRuleset(routerNamespace, nil).Server.Services; !slices.Equal(got, want) {
		t.Fatalf("router services = %+v, want that CDS and this node's verifier", got)
	}

	// A node that cannot say what its own address is names no verifier a
	// ruleset could admit.
	policy.nodeAddr = netip.Addr{}
	if got := policy.podRuleset(routerNamespace, nil).Server.Services; !slices.Equal(got, want[:1]) {
		t.Fatalf("router services = %+v, want the CDS alone", got)
	}
}

// A member pod's ruleset carries the exits it was granted and no others: the
// CDS its credential clients are bound to is theirs, not the workload's.
func TestPodRulesetCarriesOnlyTheGrantedExits(t *testing.T) {
	policy := meshRoles()
	policy.Roles = append(policy.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort("172.18.0.2:30808")},
	})

	if got := policy.podRuleset("default", nil).Exits; len(got) != 0 {
		t.Fatalf("exits of a pod granted none = %+v, want none", got)
	}
	granted := []exit{{Range: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}}
	want := []ruleset.Exit{{Range: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}}
	if got := policy.podRuleset("default", granted).Exits; !slices.Equal(got, want) {
		t.Fatalf("exits = %+v, want the granted exit alone", got)
	}
}

// Every member pod reaches each platform service the policy names, on its
// port alone, before the exits it was granted; the CDS its credential clients
// are bound to stays theirs.
func TestPodRulesetGivesEveryMemberThePolicyExits(t *testing.T) {
	policy := meshRoles()
	policy.Roles = append(policy.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort("172.18.0.2:30808")},
	})
	policy.Exits = []netip.AddrPort{netip.MustParseAddrPort("10.53.0.11:8080")}

	want := []ruleset.Exit{{Range: netip.MustParsePrefix("10.53.0.11/32"), Port: 8080}}
	for _, namespace := range []string{"default", routerNamespace} {
		if got := policy.podRuleset(namespace, nil).Exits; !slices.Equal(got, want) {
			t.Fatalf("exits of a pod in %s = %+v, want the policy's exit alone", namespace, got)
		}
	}
	granted := []exit{{Range: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}}
	want = append(want, ruleset.Exit{Range: netip.MustParsePrefix("203.0.113.7/32"), Port: 443})
	if got := policy.podRuleset("default", granted).Exits; !slices.Equal(got, want) {
		t.Fatalf("exits = %+v, want the policy's exit and the granted exit", got)
	}
}

// A policy exit must name one address and a port.
func TestMeshPolicyRefusesAnExitWithoutAPort(t *testing.T) {
	policy := meshRoles()
	policy.Exits = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("10.53.0.11"), 0)}
	if err := policy.validate(); err == nil {
		t.Fatal("mesh policy accepted an exit without a port")
	}
}

// A policy that binds no CDS leaves the router role without one, as it leaves
// the credential clients without one.
func TestPodRulesetWithoutABoundCDSServesTheRouterRoleNone(t *testing.T) {
	if server := meshRoles().podRuleset(routerNamespace, nil).Server; len(server.Services) != 0 {
		t.Fatalf("router services = %+v, want none", server.Services)
	}
}

// The injected credential clients verify CDS evidence through the
// attestation-api on their own node, so the ruleset admits that port at this
// node's address — not the CDS's, which an off-node CDS makes another host
// entirely — and the clients' identity alone reaches it.
func TestPodRulesetAdmitsTheCredentialAttestationPort(t *testing.T) {
	policy := meshRoles()
	policy.CredentialAttestationPort = 8400
	policy.nodeAddr = netip.MustParseAddr("172.18.0.2")
	policy.Roles = append(policy.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort("172.18.0.9:8443")},
	})

	var credentials ruleset.Role
	for _, role := range policy.podRuleset("default", nil).Roles {
		if role.UID == workloadclaims.CredentialsUID {
			credentials = role
		}
	}
	want := []ruleset.Destination{
		{Addr: netip.MustParseAddr("172.18.0.9"), Port: 8443},
		{Addr: netip.MustParseAddr("172.18.0.2"), Port: 8400},
	}
	if !slices.Equal(credentials.Destinations, want) {
		t.Fatalf("credential destinations = %+v, want %+v", credentials.Destinations, want)
	}
}

// The verifier a pod's ruleset admits comes from the node's own view: every
// node reads the same measured document.
func TestRulesetPolicyNamesThisNodesVerifier(t *testing.T) {
	gate := newMeshGate(*meshRoles(), slog.New(slog.DiscardHandler))
	gate.policy.CredentialAttestationPort = 8400
	gate.nodeAddress = func() (netip.Addr, error) { return netip.MustParseAddr("10.0.2.15"), nil }
	if got := gate.rulesetPolicy().nodeAddr; got != netip.MustParseAddr("10.0.2.15") {
		t.Fatalf("ruleset node address = %v, want the node's own", got)
	}
	gate.nodeAddress = func() (netip.Addr, error) { return netip.Addr{}, errors.New("unknown") }
	if got := gate.rulesetPolicy().nodeAddr; got.IsValid() {
		t.Fatalf("ruleset node address = %v, want none", got)
	}
}
