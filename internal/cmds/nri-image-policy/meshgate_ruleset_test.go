//go:build linux

package nriimagepolicy

import (
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

	server := policy.podRuleset(routerNamespace).Server
	if server.UID != workloadclaims.RouterUID {
		t.Fatalf("server uid = %d, want the reserved %d", server.UID, workloadclaims.RouterUID)
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

	member := policy.podRuleset("default")
	if member.Server.UID != 0 {
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

// The injected credential clients verify CDS evidence through the
// attestation-api on their own node, so the ruleset admits that port at the
// address their CDS is on and the clients' identity alone reaches it.
func TestPodRulesetAdmitsTheCredentialAttestationPort(t *testing.T) {
	policy := meshRoles()
	policy.CredentialAttestationPort = 8400
	policy.Roles = append(policy.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort("172.18.0.2:30808")},
	})

	var credentials ruleset.Role
	for _, role := range policy.podRuleset("default").Roles {
		if role.UID == workloadclaims.CredentialsUID {
			credentials = role
		}
	}
	want := []ruleset.Destination{
		{Addr: netip.MustParseAddr("172.18.0.2"), Port: 30808},
		{Addr: netip.MustParseAddr("172.18.0.2"), Port: 8400},
	}
	if !slices.Equal(credentials.Destinations, want) {
		t.Fatalf("credential destinations = %+v, want %+v", credentials.Destinations, want)
	}
}
