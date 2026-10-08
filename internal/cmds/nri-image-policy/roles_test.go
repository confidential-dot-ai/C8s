package nriimagepolicy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// testCertRole is a platform role the enforcer itself does not act on; the
// gate must still bind its reserved identity.
const testCertRole = "get-cert"

const (
	testMeshUID   = uint32(1337)
	testRouterUID = uint32(1339)
	// No reserved id: trusted policy refuses one of those to any other role.
	testCertUID     = workloadclaims.AcmeUID + 2
	testWorkloadUID = uint32(65532)
)

// meshRoles is a mesh policy binding the mesh endpoint and get-cert, with the
// cluster ranges the acme role's egress exception excludes.
func meshRoles() *meshPolicy {
	return &meshPolicy{
		ExemptNamespaces: []string{"kube-system"},
		Resolver:         netip.MustParseAddr("10.43.0.10"),
		Capture: capturePorts{
			Outbound: 15001,
			Inbound:  15006,
			Health:   15021,
		},
		ClusterRanges: []netip.Prefix{netip.MustParsePrefix("10.52.0.0/16")},
		Roles: []roleBinding{
			{
				Name: meshRole,
				UID:  testMeshUID,
			},
			{
				Name:         testCertRole,
				UID:          testCertUID,
				Destinations: []netip.AddrPort{netip.MustParseAddrPort("10.43.0.5:8443")},
			},
		},
	}
}

// roleBase is a base allowlist binding digest to role.
func roleBase(t *testing.T, digest, role string, argv []string) *allowlist.Allowlist {
	t.Helper()
	al := anyAllowlist(map[string]string{pushDigestA: "unrelated"})
	al.Workloads["role-entry"] = allowlist.Workload{Containers: []allowlist.Container{{
		Digest: mustDigest(t, digest),
		Role:   role,
		Command: allowlist.ArgvPolicy{
			Policy: allowlist.PolicyExact,
			Argv:   argv,
		},
		Args:   allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyAny},
	}}}
	return al
}

// A mesh policy that cannot describe a ruleset, or that leaves a role the base
// allowlist names unbound, fails at load rather than at the first member pod.
func TestMeshPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mesh   func(*meshPolicy)
		policy func(*policyConfig)
		tcb    bool
		wants  string
	}{
		{name: "bound roles", tcb: true},
		{
			name: "capture ports the mesh endpoint does not listen on",
			mesh: func(m *meshPolicy) {
				m.Capture.Health = 0
			},
			tcb:   true,
			wants: "mesh.capture needs the outbound, inbound and health port",
		},
		{
			name: "no trusted resolver",
			mesh: func(m *meshPolicy) {
				m.Resolver = netip.Addr{}
			},
			tcb:   true,
			wants: "mesh.resolver needs the address of the trusted resolver",
		},
		{
			name: "role reaching nothing",
			mesh: func(m *meshPolicy) {
				m.Roles[1].Destinations = nil
			},
			tcb:   true,
			wants: "reaches nothing",
		},
		{
			name: "two roles on one uid",
			mesh: func(m *meshPolicy) {
				m.Roles[1].UID = testMeshUID
			},
			tcb:   true,
			wants: "share uid",
		},
		{
			name: "a role on the credential clients' reserved uid",
			mesh: func(m *meshPolicy) {
				m.Roles[1].UID = workloadclaims.CredentialsUID
			},
			tcb:   true,
			wants: "reserved for the " + CredentialRole + " role",
		},
		{
			name: "the credential role reaching two addresses",
			mesh: func(m *meshPolicy) {
				m.Roles[1].Name = CredentialRole
				m.Roles[1].UID = workloadclaims.CredentialsUID
				m.Roles[1].Destinations = append(m.Roles[1].Destinations, netip.MustParseAddrPort("10.43.0.6:8443"))
			},
			tcb:   true,
			wants: "needs exactly one destination",
		},
		{
			name: "the router's namespace exempt from the mesh",
			mesh: func(m *meshPolicy) {
				m.ExemptNamespaces = append(m.ExemptNamespaces, routerNamespace)
			},
			tcb:   true,
			wants: "whose pods serve the router's ports",
		},
		{
			name: "a dialing role on the router's identity",
			mesh: func(m *meshPolicy) {
				m.Roles[0].UID = workloadclaims.RouterUID
			},
			tcb:   true,
			wants: "reserved for the " + routerRole + " role",
		},
		{
			name: "a dialing role on the egress identity",
			mesh: func(m *meshPolicy) {
				m.Roles[0].UID = workloadclaims.AcmeUID
			},
			tcb:   true,
			wants: "reserved for the " + acmeRole + " role",
		},
		{
			name:  "no mesh endpoint binding",
			mesh:  func(m *meshPolicy) { m.Roles = m.Roles[1:] },
			tcb:   true,
			wants: "binds no reserved uid to the mesh role",
		},
		{
			// The install lane: the chart renders both the base and the mesh
			// policy, so holding it to the baked lane's enforcement would only
			// refuse a test cluster the same admin configured.
			name: "chart-rendered mesh policy on the install lane",
			policy: func(p *policyConfig) {
				p.Mode = ModeAudit
				p.FatalExisting = false
			},
		},
		{
			name: "admission in audit mode",
			tcb:  true,
			policy: func(p *policyConfig) {
				p.Mode = ModeAudit
			},
			wants: "policy.fatal_existing",
		},
		{
			name: "admission carve-out the mesh does not exempt",
			tcb:  true,
			policy: func(p *policyConfig) {
				p.ExemptNamespaces = []string{"kube-system", "platform"}
			},
			wants: "must also be in mesh.exempt_namespaces",
		},
		{
			name: "no boot gate",
			tcb:  true,
			policy: func(p *policyConfig) {
				p.FatalExisting = false
			},
			wants: "trusted enforcement from node startup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mesh := meshRoles()
			if tc.mesh != nil {
				tc.mesh(mesh)
			}
			base := roleBase(t, pushDigestB, testCertRole, []string{"/usr/local/bin/c8s", "get-cert"})
			policy := policyConfig{
				Mode:          ModeFailClosed,
				FatalExisting: true,
			}
			if tc.policy != nil {
				tc.policy(&policy)
			}
			cfg := &config{
				Allowlist: allowlistConfig{
					Base:    base,
					NodeTCB: tc.tcb,
				},
				Policy: policy,
				Mesh:   mesh,
			}
			err := cfg.validateMesh()
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("rejected a valid mesh policy: %v", err)
			case tc.wants == "":
				if _, bound := cfg.Mesh.role(testCertRole); !bound {
					t.Fatal("a valid mesh policy bound no get-cert role")
				}
			case err == nil:
				t.Fatalf("accepted %s", tc.name)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// The mesh policy's addresses are parsed by the config loader, so a resolver
// or destination that names no address fails the node's start.
func TestMeshPolicyAddressesAreParsedAtLoad(t *testing.T) {
	document := func(resolver, destination string) []byte {
		return []byte(`
allowlist:
  node_tcb: true
  base:
    schema: ` + allowlist.Schema + `
    workloads:
      mesh:
        containers:
          - digest: "` + pushDigestA + `"
            role: mesh
            command: {policy: any}
            args: {policy: any}
            mounts: {policy: any}
policy:
  mode: fail-closed
  fatal_existing: true
  boot_marker_path: /run/nri-image-policy/registered
mesh:
  resolver: "` + resolver + `"
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
    - name: get-cert
      uid: 1341
      destinations: ["` + destination + `"]
`)
	}
	cfg, err := parseConfig(document("10.43.0.10", "10.43.0.5:8443"))
	if err != nil {
		t.Fatalf("a valid mesh policy was refused: %v", err)
	}
	if cfg.Mesh.Resolver.String() != "10.43.0.10" {
		t.Fatalf("resolver = %v", cfg.Mesh.Resolver)
	}
	if _, err := parseConfig(document("cluster.local", "10.43.0.5:8443")); err == nil {
		t.Fatal("a resolver that is no address was accepted")
	}
	if _, err := parseConfig(document("10.43.0.10", "10.43.0.5")); err == nil {
		t.Fatal("a destination without a port was accepted")
	}
}

// A role the mesh policy binds nowhere holds no reserved identity, so the gate
// refuses its container rather than running it unconfined.
func TestUnboundRoleRefusesItsContainer(t *testing.T) {
	policy := meshPolicy{Roles: []roleBinding{{Name: meshRole, UID: testMeshUID}}}
	ctr := &api.Container{Name: "c8s-cert", User: &api.User{Uid: testCertUID}}
	err := policy.requireRoleIdentity(ctr, testCertRole)
	if err == nil || !strings.Contains(err.Error(), "no reserved uid is bound") {
		t.Fatalf("error = %v, want the unbound-role refusal", err)
	}
}

// A role is granted to a verified identity from the node's own measured base:
// a served document carries none, a chart-rendered base binds none, and an
// argv the declaration does not admit binds none.
func TestRoleOfBindsOnlyTheMeasuredIdentity(t *testing.T) {
	argv := []string{"/usr/local/bin/c8s", "get-cert"}
	base := roleBase(t, pushDigestB, testCertRole, argv)
	served := roleBase(t, pushDigestB, testCertRole, argv)
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{
			Base:    base,
			NodeTCB: true,
		},
		Policy: policyConfig{
			Mode:          ModeFailClosed,
			FatalExisting: true,
		},
	}, served)

	launch := allowlist.RunningContainer{
		Digest: pushDigestB,
		Argv:   argv,
	}
	if got := p.roleOf(launch); got != testCertRole {
		t.Fatalf("role = %q, want %q", got, testCertRole)
	}
	otherArgv := allowlist.RunningContainer{
		Digest: pushDigestB,
		Argv:   []string{"/bin/sh"},
	}
	if got := p.roleOf(otherArgv); got != "" {
		t.Fatalf("another argv took the role: %q", got)
	}
	otherImage := allowlist.RunningContainer{
		Digest: pushDigestA,
		Argv:   argv,
	}
	if got := p.roleOf(otherImage); got != "" {
		t.Fatalf("another image took the role: %q", got)
	}

}

// The role field never travels on the wire, so nothing a CDS serves can claim
// one.
func TestRoleIsNotServed(t *testing.T) {
	base := roleBase(t, pushDigestB, testCertRole, []string{"/usr/local/bin/c8s"})
	wire, err := base.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), testCertRole) {
		t.Fatalf("the canonical document carries a role: %s", wire)
	}
	served, err := allowlist.ParseServedJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := served.BuildIndex().RoleOf(allowlist.RunningContainer{Digest: pushDigestB}); got != "" {
		t.Fatalf("a served document bound the %q role", got)
	}
}

// A reserved UID belongs to its role: the role's container must run as it, and
// every other container must claim it nowhere — not as its user, its group or
// a supplementary group.
func TestRequireRoleIdentity(t *testing.T) {
	policy := *meshRoles()
	for _, tc := range []struct {
		name    string
		role    string
		user    *api.User
		refused bool
	}{
		{name: "role on its own uid", role: testCertRole, user: &api.User{Uid: testCertUID, Gid: testCertUID}},
		{name: "role on another uid", role: testCertRole, user: &api.User{Uid: testWorkloadUID}, refused: true},
		{name: "workload on its own uid", user: &api.User{Uid: testWorkloadUID, Gid: testWorkloadUID}},
		{name: "workload on a reserved uid", user: &api.User{Uid: testMeshUID}, refused: true},
		{name: "workload on a reserved gid", user: &api.User{Uid: testWorkloadUID, Gid: testMeshUID}, refused: true},
		{
			name:    "workload on a reserved supplementary group",
			user:    &api.User{Uid: testWorkloadUID, AdditionalGids: []uint32{testCertUID}},
			refused: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := policy.requireRoleIdentity(&api.Container{User: tc.user}, tc.role)
			if (err != nil) != tc.refused {
				t.Fatalf("requireRoleIdentity = %v, refused=%v", err, tc.refused)
			}
		})
	}
}

// The router's compiled ports and identities carry the invariants the policy
// schema used to restate: the platform identities are distinct, so the acme
// role alone holds the egress ports and a connection the router forwards is
// captured wherever its name resolves; and no port the router answers on or
// reaches is a mesh listener port, whose traffic belongs to the pod's endpoint
// alone.
func TestTheRoutersCompiledPortsAndIdentitiesCollideWithNothing(t *testing.T) {
	roles := map[uint32]string{
		workloadclaims.MeshUID:        meshRole,
		workloadclaims.CredentialsUID: CredentialRole,
		workloadclaims.RouterUID:      routerRole,
		workloadclaims.AcmeUID:        acmeRole,
	}
	if len(roles) != 4 {
		t.Errorf("the platform roles share a reserved identity: %v", roles)
	}
	capture := []uint16{
		uint16(workloadclaims.MeshOutboundPort),
		uint16(workloadclaims.MeshInboundPort),
		uint16(workloadclaims.MeshHealthPort),
	}
	for _, port := range slices.Concat(routerListeners, acmeEgressPorts) {
		if port == 0 || slices.Contains(capture, port) {
			t.Errorf("the router holds port %d, which belongs to the pod's mesh endpoint", port)
		}
	}
}
