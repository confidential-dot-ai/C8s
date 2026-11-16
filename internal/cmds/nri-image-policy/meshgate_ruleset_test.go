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
	// nginx's identity holds no egress port, so a connection it relays
	// outside the cluster is captured, not passed.
	if server.Egress.UID != workloadclaims.AcmeUID {
		t.Fatalf("server egress = %+v, want the reserved %d", server.Egress, workloadclaims.AcmeUID)
	}
	if ranges := policy.podRuleset(routerNamespace, nil).ClusterRanges; len(ranges) != 1 {
		t.Fatalf("cluster ranges = %v, want the measured range", ranges)
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

// A member pod's ruleset carries the exits it was granted and no others: the
// CDS its credential clients are bound to is theirs, not the workload's.
func TestPodRulesetCarriesOnlyTheGrantedExits(t *testing.T) {
	policy := meshRoles()
	policy.Roles = append(policy.Roles, roleBinding{
		Name: CredentialRole,
		UID:  workloadclaims.CredentialsUID,
		Port: 30808,
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

// The injected credential clients verify CDS evidence through the
// attestation-api on their own node, so the ruleset admits that port at this
// node's address — not the CDS's, which an off-node CDS makes another host
// entirely — and the clients' identity alone reaches it.
func TestPodRulesetAdmitsTheCredentialAttestationPort(t *testing.T) {
	policy := meshRoles()
	policy.CredentialAttestationPort = 8400
	policy.nodeAddr = netip.MustParseAddr("172.18.0.2")
	policy.Roles = append(policy.Roles, roleBinding{
		Name: CredentialRole,
		UID:  workloadclaims.CredentialsUID,
		Port: 8443,
	})

	var credentials ruleset.Role
	for _, role := range policy.podRuleset("default", nil).Roles {
		if role.UID == workloadclaims.CredentialsUID {
			credentials = role
		}
	}
	want := []ruleset.Destination{{Addr: netip.MustParseAddr("172.18.0.2"), Port: 8400}}
	if !slices.Equal(credentials.Destinations, want) {
		t.Fatalf("credential destinations = %+v, want %+v", credentials.Destinations, want)
	}
	if credentials.OutsidePort != 8443 {
		t.Fatalf("credential outside port = %d, want the port its CDS serves on", credentials.OutsidePort)
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

// Standalone Pod capture stays distinct from the member policy's CDS port
// exceptions when both are rendered through podRuleset.
func TestStandalonePodRulesetKeepsSignedPeersWithoutCredentialBypass(t *testing.T) {
	policy := meshRoles()
	policy.Roles = policy.Roles[:1]
	policy.ClusterRanges = nil
	peer := netip.MustParseAddrPort("203.0.113.7:8443")
	policy.Pod = &podMeshPolicy{Peers: []netip.AddrPort{peer}}
	got := policy.podRuleset("tenant", nil)
	want := []ruleset.Destination{{Addr: peer.Addr(), Port: peer.Port()}}
	if got.Pod == nil || !slices.Equal(got.Pod.Peers, want) {
		t.Fatalf("standalone capture = %+v, want signed peer %v", got.Pod, want)
	}
	if len(got.Roles) != 0 || got.Server.Upstream != 0 {
		t.Fatalf("standalone Pod gained platform exceptions: %+v", got)
	}
}
