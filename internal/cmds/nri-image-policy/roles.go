package nriimagepolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The platform roles the enforcer acts on itself: the mesh endpoint, whose
// start opens a pod's gate, and the router, which serves on ports of its own.
// Trusted policy names a role on a declared container of the measured base
// allowlist, and the enforcer grants it to a container whose verified identity
// matches that declaration — never to a name or annotation a pod carries.
const (
	meshRole   = "mesh"
	routerRole = "router"
	// CredentialRole is the role of the injected credential clients. A node's
	// boot preparation binds it to that cluster's CDS address, so the name is
	// shared rather than written twice.
	CredentialRole = "credentials"
)

// meshPolicy is the trusted mesh policy: the pod ruleset's inputs and the
// reserved UID each platform role runs as. A measured config carrying no mesh
// policy hosts no member pods.
type meshPolicy struct {
	// ExemptNamespaces host no member pods: their pods keep the node's rules.
	ExemptNamespaces []string `yaml:"exempt_namespaces"`
	// Resolver is the address the ruleset admits on the resolver port.
	Resolver netip.Addr `yaml:"resolver"`
	// Capture are the mesh endpoint's own listen ports in its pod.
	Capture capturePorts  `yaml:"capture"`
	Roles   []roleBinding `yaml:"roles"`
}

type capturePorts struct {
	Outbound uint16 `yaml:"outbound"`
	Inbound  uint16 `yaml:"inbound"`
	Health   uint16 `yaml:"health"`
}

// roleBinding binds a role to its reserved UID and what it may reach. The
// mesh endpoint names nothing: the enforcer installs the pod ruleset, so the
// endpoint only proxies.
type roleBinding struct {
	Name         string           `yaml:"name"`
	UID          uint32           `yaml:"uid"`
	Destinations []netip.AddrPort `yaml:"destinations"`
}

// MeshFloor is the measured mesh policy as the node's runtime wrapper reads
// it: the namespaces that host no member pods, and what the role behind each
// reserved id may hold. Trusted policy reserves that number as both a UID and
// a GID (internal/cmds/c8srunc).
type MeshFloor struct {
	ExemptNamespaces []string
	ReservedIDs      map[uint32]RoleFloor
}

// RoleFloor is one platform role as the floor reads it.
type RoleFloor struct {
	Name string
}

// LoadMeshFloor reads the measured config and returns its mesh floor, or nil
// when the config carries no mesh policy and the node hosts no member pods.
// validate refuses two roles on one UID, so no reserved id names two roles.
func LoadMeshFloor(configPath string) (*MeshFloor, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if cfg.Mesh == nil {
		return nil, nil
	}
	floor := &MeshFloor{
		ExemptNamespaces: cfg.Mesh.ExemptNamespaces,
		ReservedIDs:      map[uint32]RoleFloor{},
	}
	for _, role := range cfg.Mesh.Roles {
		floor.ReservedIDs[role.UID] = RoleFloor{Name: role.Name}
	}
	return floor, nil
}

// validate requires a policy the pod ruleset can be built from, at config
// load: a node whose mesh policy describes no ruleset refuses to start. A
// role this policy does not bind holds no identity, so the gate refuses it.
func (p meshPolicy) validate() error {
	if p.Capture.Outbound == 0 || p.Capture.Inbound == 0 || p.Capture.Health == 0 {
		return errors.New("mesh.capture needs the outbound, inbound and health port of the mesh endpoint")
	}
	if !p.Resolver.IsValid() {
		return errors.New("mesh.resolver needs the address of the trusted resolver")
	}
	uids := map[uint32]string{}
	for _, role := range p.Roles {
		if role.Name != meshRole && len(role.Destinations) == 0 {
			return fmt.Errorf("mesh.roles %s reaches nothing: give it a destination or drop it", role.Name)
		}
		if role.Name == CredentialRole && len(role.Destinations) != 1 {
			return fmt.Errorf("mesh.roles %s needs exactly one destination, the CDS its clients dial", CredentialRole)
		}
		if role.Name != CredentialRole && role.UID == workloadclaims.CredentialsUID {
			return fmt.Errorf("mesh.roles %s holds uid %d, reserved for the %s role", role.Name, role.UID, CredentialRole)
		}
		if owner, taken := uids[role.UID]; taken {
			return fmt.Errorf("mesh.roles %s and %s share uid %d", owner, role.Name, role.UID)
		}
		uids[role.UID] = role.Name
	}
	if _, bound := p.role(meshRole); !bound {
		return errors.New("mesh.roles binds no reserved uid to the mesh role")
	}
	return nil
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
	bound, ok := p.role(role)
	switch {
	case !ok:
		return fmt.Errorf("no reserved uid is bound to the %s role", role)
	case ctr.GetUser().GetUid() != bound.UID:
		return fmt.Errorf("the %s role runs as uid %d, not %d", role, bound.UID, ctr.GetUser().GetUid())
	}
	return p.requireUnreservedIdentity(ctr, role)
}

// requireUnreservedIdentity refuses a reserved identity outside the role a
// container holds — user, group or supplementary group — because the pod
// ruleset grants a role's traffic permissions by socket UID.
func (p meshPolicy) requireUnreservedIdentity(ctr *api.Container, role string) error {
	user := ctr.GetUser()
	for _, id := range append([]uint32{user.GetUid(), user.GetGid()}, user.GetAdditionalGids()...) {
		i := slices.IndexFunc(p.Roles, func(r roleBinding) bool {
			return r.UID == id && r.Name != role
		})
		if i >= 0 {
			return fmt.Errorf("uid or gid %d is reserved for the %s role", id, p.Roles[i].Name)
		}
	}
	return nil
}
