package nriimagepolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The platform roles the enforcer acts on itself, each with the identity it
// reserves (pkg/workloadclaims). Trusted policy names a role on a declared
// container of the measured base allowlist, and the enforcer grants it to a
// container whose verified identity matches that declaration — never to a
// name or annotation a pod carries.
const (
	// meshRole is the pod's own endpoint, whose start opens the gate for the
	// rest of the pod.
	meshRole = workloadclaims.MeshRole
	// CredentialRole is the role of the injected credential clients. A node's
	// boot preparation binds it to that cluster's CDS address, so the name is
	// shared rather than written twice.
	CredentialRole = workloadclaims.CredentialsRole
	// routerRole answers the cluster's external traffic on ports of its own,
	// in the router's namespace.
	routerRole = "router"
	// acmeRole is the one role of that namespace whose sockets leave the
	// cluster in the clear.
	acmeRole = "acme"
	// upstreamRole is that namespace's route authority: it holds the signed
	// route manifest and reaches the cluster uncaptured, as a mesh client of
	// the backend each route names.
	upstreamRole = "upstream"
)

// routerNamespace is the namespace whose pods serve the router's ports. The
// chart renders that pod itself, so nothing per-cluster chooses the name.
const routerNamespace = workloadclaims.RouterNamespace

// The ports of the router's namespace that cross the pod boundary in the
// clear. A listener is uncaptured in both directions, so the kubelet reaches
// it; the egress ports are the acme role's alone, so a request the router
// forwards outside the cluster is captured wherever its name resolves.
//
// INVARIANT: routerListeners are the container ports the chart's router pod
// binds (router.nginx.httpsPort, the HTTP-01 port and the acme sidecar's
// readiness port), and acmeEgressPorts are the ports public certificate
// issuance uses: the directory the sidecar orders from, and the plain HTTP
// port each public name is checked on before validation.
var (
	routerListeners = []uint16{8443, 8080, 8403}
	acmeEgressPorts = []uint16{443, 80}
)

// meshPolicy is the trusted mesh policy: the pod ruleset's inputs and the
// reserved UID each platform role runs as.
type meshPolicy struct {
	// ExemptNamespaces host no member pods: their pods keep the node's rules.
	ExemptNamespaces []string `yaml:"exempt_namespaces"`
	// Resolver is the address the ruleset admits on the resolver port.
	Resolver netip.Addr `yaml:"resolver"`
	// Capture are the mesh endpoint's own listen ports in its pod.
	Capture capturePorts `yaml:"capture"`
	// CredentialAttestationPort is the port on this node's own address the
	// injected credential clients verify evidence through, where no node-local
	// socket serves the attestation-api. 0 names none.
	CredentialAttestationPort uint16        `yaml:"credential_attestation_port"`
	Roles                     []roleBinding `yaml:"roles"`
	// ClusterRanges are this cluster's pod and Service ranges. A destination
	// inside them is a member, so the acme egress exception excludes them and
	// that traffic is captured like any other application connection.
	ClusterRanges []netip.Prefix `yaml:"cluster_ranges"`
	// Pod restricts a guest endpoint to the signed peer and ingress tuples.
	Pod *podMeshPolicy `yaml:"pod,omitempty"`
}

type podMeshPolicy struct {
	Peers        []netip.AddrPort `yaml:"peers"`
	IngressPorts []uint16         `yaml:"ingress_ports"`
}

type capturePorts struct {
	Outbound uint16 `yaml:"outbound"`
	Inbound  uint16 `yaml:"inbound"`
	Health   uint16 `yaml:"health"`
}

// roleBinding binds a dialing role to its reserved UID and the services it
// may reach. The mesh endpoint names none: the enforcer installs the pod
// ruleset, so the endpoint only proxies.
type roleBinding struct {
	Name         string           `yaml:"name"`
	UID          uint32           `yaml:"uid"`
	Destinations []netip.AddrPort `yaml:"destinations"`
}

// MeshFloor is the measured mesh policy as the mesh gate and the node's
// runtime wrapper read it: the namespaces that host no member pods, what the
// role behind each reserved id may hold, and whether the policy is a pod
// CVM's. Trusted policy reserves that number as both a UID and a GID
// (internal/cmds/c8srunc).
type MeshFloor struct {
	ExemptNamespaces []string
	ReservedIDs      map[uint32]RoleFloor
	// PodRole marks the policy of a pod CVM, which runs one pod: its floor
	// admits a root user outside every role, since no other tenant shares
	// the kernel, and every workload start requires a live admission permission.
	// validatePod ties mesh.pod to the pod role's other markers.
	PodRole bool
}

// RequireUnreservedIdentity is the one identity verdict the mesh gate and the
// runtime wrapper apply: no container claims an id reserved for another role,
// as user, group or supplementary group, because the pod ruleset grants a
// role's traffic permissions by socket UID; and on a node a container outside
// every role runs as a non-root user. A pod CVM admits root there: what root
// can do is bounded by the runtime wrapper's capability, no_new_privs and
// namespace rules, which keep SETUID and SETGID out, so it cannot take a
// reserved socket identity.
func (f MeshFloor) RequireUnreservedIdentity(uid, gid uint32, supplementary []uint32, role string) error {
	if role == "" && uid == 0 && !f.PodRole {
		return errors.New("a container outside every platform role runs as root")
	}
	if owner, reserved := f.ReservedIDs[uid]; reserved && owner.Name != role {
		return fmt.Errorf("uid %d is reserved for the %s role", uid, owner.Name)
	}
	for _, id := range append([]uint32{gid}, supplementary...) {
		if owner, reserved := f.ReservedIDs[id]; reserved && owner.Name != role {
			return fmt.Errorf("gid %d is reserved for the %s role", id, owner.Name)
		}
	}
	return nil
}

// RoleFloor is one platform role as the floor reads it.
type RoleFloor struct {
	Name string
}

// LoadMeshFloor reads the measured config and returns its mesh floor.
// validate refuses two roles on one UID, so no reserved id names two roles.
func LoadMeshFloor(configPath string) (MeshFloor, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return MeshFloor{}, err
	}
	return cfg.Mesh.floor(), nil
}

// floor is the policy as its identity floor.
func (p meshPolicy) floor() MeshFloor {
	floor := MeshFloor{
		ExemptNamespaces: p.ExemptNamespaces,
		ReservedIDs:      map[uint32]RoleFloor{},
		PodRole:          p.Pod != nil,
	}
	for role, reserved := range p.reservedIdentities() {
		floor.ReservedIDs[reserved] = RoleFloor{Name: role}
	}
	return floor
}

// validate requires a policy the pod ruleset can be built from, at config
// load: a node whose mesh policy describes no ruleset refuses to start. A
// role this policy does not bind holds no identity, so the gate refuses it.
func (p meshPolicy) validate() error {
	if p.Capture.Outbound == 0 || p.Capture.Inbound == 0 || p.Capture.Health == 0 {
		return errors.New("mesh.capture needs the outbound, inbound and health port of the mesh endpoint")
	}
	if p.Capture.Outbound == p.Capture.Inbound || p.Capture.Outbound == p.Capture.Health || p.Capture.Inbound == p.Capture.Health {
		return errors.New("mesh.capture ports must be distinct")
	}
	if !p.Resolver.IsValid() {
		return errors.New("mesh.resolver needs the address of the trusted resolver")
	}
	for _, in := range p.ClusterRanges {
		if !in.IsValid() || in.Addr().Is4In6() || in != in.Masked() {
			return fmt.Errorf("mesh.cluster_ranges %s is not a masked prefix of one address family", in)
		}
	}
	if slices.Contains(p.ExemptNamespaces, routerNamespace) {
		return fmt.Errorf("mesh.exempt_namespaces lists %s, whose pods serve the router's ports and are members", routerNamespace)
	}
	if err := p.validateRoles(); err != nil {
		return err
	}
	if _, bound := p.role(meshRole); !bound {
		return errors.New("mesh.roles binds no reserved uid to the mesh role")
	}
	return nil
}

// validateRoles requires every dialing role to be one the enforcer can grant,
// and no two of them to hold one identity.
func (p meshPolicy) validateRoles() error {
	uids := map[uint32]string{}
	for _, role := range p.Roles {
		if err := validateRole(role); err != nil {
			return err
		}
		if owner, taken := uids[role.UID]; taken {
			return fmt.Errorf("mesh.roles %s and %s share uid %d", owner, role.Name, role.UID)
		}
		uids[role.UID] = role.Name
	}
	return nil
}

// validateRole requires one dialing role to name what it reaches and to hold
// no identity another role's rules are written for.
func validateRole(role roleBinding) error {
	if role.UID == 0 {
		return fmt.Errorf("mesh.roles %s requires a nonzero uid", role.Name)
	}
	for _, destination := range role.Destinations {
		if destination.Port() == 0 {
			return fmt.Errorf("mesh.roles %s destination %s requires a nonzero port", role.Name, destination)
		}
	}
	switch {
	case role.Name != meshRole && len(role.Destinations) == 0:
		return fmt.Errorf("mesh.roles %s reaches nothing: give it a destination or drop it", role.Name)
	case role.Name == CredentialRole && len(role.Destinations) != 1:
		return fmt.Errorf("mesh.roles %s needs exactly one destination, the CDS its clients dial", CredentialRole)
	case role.Name != CredentialRole && role.UID == workloadclaims.CredentialsUID:
		return fmt.Errorf("mesh.roles %s holds uid %d, reserved for the %s role", role.Name, role.UID, CredentialRole)
	case role.Name == routerRole || role.Name == acmeRole || role.Name == upstreamRole:
		return fmt.Errorf("mesh.roles %s is a compiled role of the router's namespace, not a dialing role", role.Name)
	case role.UID == workloadclaims.RouterUID:
		return fmt.Errorf("mesh.roles %s holds uid %d, reserved for the %s role", role.Name, role.UID, routerRole)
	case role.UID == workloadclaims.AcmeUID:
		return fmt.Errorf("mesh.roles %s holds uid %d, reserved for the %s role", role.Name, role.UID, acmeRole)
	case role.UID == workloadclaims.UpstreamUID:
		return fmt.Errorf("mesh.roles %s holds uid %d, reserved for the %s role", role.Name, role.UID, upstreamRole)
	}
	return nil
}

// reservedIdentities pairs every platform role with the identity it reserves:
// the dialing roles trusted policy binds, and the three compiled roles of the
// router's namespace.
func (p meshPolicy) reservedIdentities() map[string]uint32 {
	ids := make(map[string]uint32, len(p.Roles)+3)
	for _, role := range p.Roles {
		ids[role.Name] = role.UID
	}
	ids[routerRole] = workloadclaims.RouterUID
	ids[acmeRole] = workloadclaims.AcmeUID
	ids[upstreamRole] = workloadclaims.UpstreamUID
	return ids
}

func (p meshPolicy) role(name string) (roleBinding, bool) {
	i := slices.IndexFunc(p.Roles, func(r roleBinding) bool {
		return r.Name == name
	})
	if i < 0 {
		return roleBinding{}, false
	}
	return p.Roles[i], true
}

// requireRoleIdentity requires a role's container to run as that role's
// reserved UID, and no container to claim an identity outside its role.
func (p meshPolicy) requireRoleIdentity(ctr *api.Container, role string) error {
	if role == "" {
		return p.requireUnreservedIdentity(ctr, "")
	}
	reserved, bound := p.reservedIdentities()[role]
	switch {
	case !bound:
		return fmt.Errorf("no reserved uid is bound to the %s role", role)
	case ctr.GetUser().GetUid() != reserved:
		return fmt.Errorf("the %s role runs as uid %d, not %d", role, reserved, ctr.GetUser().GetUid())
	}
	return p.requireUnreservedIdentity(ctr, role)
}

// requireUnreservedIdentity applies the floor's identity verdict
// (MeshFloor.RequireUnreservedIdentity) to a container the gate admits.
func (p meshPolicy) requireUnreservedIdentity(ctr *api.Container, role string) error {
	user := ctr.GetUser()
	return p.floor().RequireUnreservedIdentity(user.GetUid(), user.GetGid(), user.GetAdditionalGids(), role)
}
