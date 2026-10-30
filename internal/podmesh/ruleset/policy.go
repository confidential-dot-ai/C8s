//go:build linux

// Package ruleset builds, installs and verifies the nftables ruleset that
// protects one mesh member pod.
//
// The ruleset comes from trusted policy alone and carries no pod address, so
// one expected ruleset covers every member pod on a node: a host-side caller
// holding the pod's network namespace path installs it before any container of
// that pod runs. Application TCP is redirected to the pod's own mesh
// listeners; everything else is denied in both directions, apart from
// loopback, pod-local addresses, neighbour discovery, the resolver trusted
// policy names, the pod's exits, and the destinations each platform role is
// bound to.
package ruleset

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// resolverPort is the only destination port the resolver exception permits.
const resolverPort = 53

// ErrPolicy reports trusted policy no ruleset can be built from.
var ErrPolicy = errors.New("pod ruleset policy")

// Policy is the trusted input the ruleset is built from.
type Policy struct {
	// Resolver is the one address a member pod may reach on the resolver
	// port, over UDP and TCP.
	Resolver netip.Addr
	Capture  CapturePorts
	// MeshUID owns sockets that are neither captured nor confined to a
	// destination: the mesh endpoint authenticates its own peers.
	MeshUID uint32
	Roles   []Role
	// ClusterRanges are this cluster's pod and Service ranges: a role's
	// outside port stops at them, the server role's egress exception
	// excludes them, and its upstream identity reaches them uncaptured.
	ClusterRanges []netip.Prefix
	// Exits are the destinations every socket of the pod but root's reaches
	// over TCP uncaptured. Each is a way out of the pod for whatever the
	// application sends, so only trusted policy names one.
	Exits []Exit
	// Server is the platform role whose own ports this pod serves, where the
	// caller builds it for a pod of the router's namespace. Its application
	// traffic is captured like a workload's, and only its external listener
	// ports and its egress identity's ports pass the pod boundary in the
	// clear.
	Server ServerRole
}

// ServerRole is the platform role a pod serves external traffic for: the ports
// it answers on itself, the one port one identity of that pod may reach
// outside the cluster, and the identity that reaches the cluster itself. An
// inbound accept cannot name a socket UID, so the listeners belong to the
// ruleset of that pod and to no other.
type ServerRole struct {
	Listeners []uint16
	Egress    ServerEgress
	// Upstream is the identity of the pod's route authority: it holds the
	// signed route manifest and dials the member each route names as a mesh
	// client, so its connections to ClusterRanges are left to it rather than
	// captured, and it is the one identity here that reaches Services.
	Upstream uint32
	// Services are the destinations the upstream identity reaches in the
	// clear, each one address and port: the verifier that weighs the
	// evidence of the CDS it fetches the signed route manifest from.
	Services []Destination
	// OutsidePort is the port that identity reaches on any address outside
	// the cluster: where that CDS serves. 0 names none.
	OutsidePort uint16
}

// ServerEgress is the one identity of a server-role pod whose sockets leave
// the cluster in the clear, and the ports they leave on. It is never the
// identity that forwards application traffic: a forwarded connection whose
// destination resolves outside the cluster is captured, not passed.
type ServerEgress struct {
	UID   uint32
	Ports []uint16
}

// serves reports whether this pod answers any port of its own.
func (s ServerRole) serves() bool {
	return len(s.Listeners) > 0
}

// reaches reports whether any rule of this role would name an identity of the
// pod, which only a pod that serves the role's own ports carries.
func (s ServerRole) reaches() bool {
	return s.Upstream != 0 || s.OutsidePort != 0 || len(s.Services) > 0 || len(s.Egress.Ports) > 0
}

// CapturePorts are the ports the mesh endpoint listens on in its pod.
type CapturePorts struct {
	Outbound uint16
	Inbound  uint16
	Health   uint16
}

// Role is one platform role bound to a reserved UID, with what that role's
// containers may reach outside the mesh listeners.
type Role struct {
	UID          uint32
	Destinations []Destination
	// OutsidePort is one TCP port this role reaches on any address outside
	// Policy.ClusterRanges: where this cluster's CDS serves. Trusted policy
	// names that CDS by <host>:<port>, and the name is resolved by whatever
	// dials it, so no rule can name its address. 0 names none.
	OutsidePort uint16
}

// Exit is one range and one TCP port the pod reaches uncaptured.
type Exit struct {
	Range netip.Prefix
	Port  uint16
}

// Destination is one address and port a role may reach.
type Destination struct {
	Addr netip.Addr
	Port uint16
}

// validate rejects policy whose ruleset would be wider than intended.
func (p Policy) validate() error {
	if err := p.Capture.validate(); err != nil {
		return err
	}
	if err := validRemoteAddress(p.Resolver); err != nil {
		return err
	}
	if p.MeshUID == 0 {
		return fmt.Errorf("%w: mesh UID is root", ErrPolicy)
	}
	bound := map[uint32]bool{p.MeshUID: true}
	for _, role := range p.Roles {
		if bound[role.UID] {
			return fmt.Errorf("%w: UID %d bound twice", ErrPolicy, role.UID)
		}
		bound[role.UID] = true
		if err := role.validate(); err != nil {
			return err
		}
		if err := p.requireClusterRanges(role.UID, role.OutsidePort); err != nil {
			return err
		}
	}
	for _, exit := range p.Exits {
		if err := exit.validate(); err != nil {
			return err
		}
	}
	for _, in := range p.ClusterRanges {
		if err := validClusterRange(in); err != nil {
			return err
		}
	}
	return p.validateServer()
}

// requireClusterRanges refuses a port reached outside this cluster with no
// ranges saying where outside begins: the accept would reach every member pod
// and every Service on that port.
func (p Policy) requireClusterRanges(uid uint32, port uint16) error {
	if port == 0 || len(p.ClusterRanges) > 0 {
		return nil
	}
	return fmt.Errorf("%w: UID %d reaches port %d with no cluster ranges to stop it inside this cluster", ErrPolicy, uid, port)
}

// validate requires an exit one rule can match, to hosts outside the pod.
func (e Exit) validate() error {
	switch {
	case !e.Range.IsValid():
		return fmt.Errorf("%w: invalid exit range", ErrPolicy)
	case e.Range != e.Range.Masked():
		return fmt.Errorf("%w: exit range %s carries host bits", ErrPolicy, e.Range)
	case e.Port == 0:
		return fmt.Errorf("%w: exit %s has no port", ErrPolicy, e.Range)
	}
	if special, overlaps := allowlist.NonUnicastOverlap(e.Range); overlaps {
		return fmt.Errorf("%w: exit range %s overlaps %s", ErrPolicy, e.Range, special)
	}
	return nil
}

// validate rejects a server role no ruleset can carry. Its identities and its
// ports are compiled in (internal/cmds/nri-image-policy), so the cluster
// ranges its egress exception excludes are the one input left: an exception
// that excludes none would carry a forwarded connection to a member out of
// the pod in the clear.
func (p Policy) validateServer() error {
	if !p.Server.serves() {
		if p.Server.reaches() {
			return fmt.Errorf("%w: a server role that answers no port of its own reaches nothing, so no rule may name its identities", ErrPolicy)
		}
		return nil
	}
	if p.Server.Upstream == 0 {
		return fmt.Errorf("%w: server role has no upstream identity, so its uncaptured cluster rules would match root", ErrPolicy)
	}
	if len(p.Server.Egress.Ports) > 0 && len(p.ClusterRanges) == 0 {
		return fmt.Errorf("%w: server role UID %d has egress ports and no cluster ranges to exclude from them", ErrPolicy, p.Server.Egress.UID)
	}
	if err := p.requireClusterRanges(p.Server.Upstream, p.Server.OutsidePort); err != nil {
		return err
	}
	for _, dst := range p.Server.Services {
		if err := validRemoteAddress(dst.Addr); err != nil {
			return err
		}
		if dst.Port == 0 {
			return fmt.Errorf("%w: upstream identity %d service %s has no port", ErrPolicy, p.Server.Upstream, dst.Addr)
		}
	}
	return nil
}

// validClusterRange requires a range one rule can match: a masked prefix of
// one family.
func validClusterRange(in netip.Prefix) error {
	switch {
	case !in.IsValid():
		return fmt.Errorf("%w: invalid cluster range", ErrPolicy)
	case in.Addr().Is4In6():
		return fmt.Errorf("%w: 4-in-6 cluster range %s", ErrPolicy, in)
	case in != in.Masked():
		return fmt.Errorf("%w: cluster range %s carries host bits", ErrPolicy, in)
	}
	return nil
}

func (c CapturePorts) validate() error {
	switch {
	case c.Outbound == 0 || c.Inbound == 0 || c.Health == 0:
		return fmt.Errorf("%w: incomplete capture ports", ErrPolicy)
	case c.Outbound == c.Inbound || c.Outbound == c.Health || c.Inbound == c.Health:
		return fmt.Errorf("%w: capture ports collide", ErrPolicy)
	}
	return nil
}

func (r Role) validate() error {
	if r.UID == 0 {
		return fmt.Errorf("%w: role UID is root", ErrPolicy)
	}
	if len(r.Destinations) == 0 && r.OutsidePort == 0 {
		return fmt.Errorf("%w: role UID %d reaches nothing", ErrPolicy, r.UID)
	}
	for _, dst := range r.Destinations {
		if err := validRemoteAddress(dst.Addr); err != nil {
			return err
		}
		if dst.Port == 0 {
			return fmt.Errorf("%w: role UID %d destination %s has no port", ErrPolicy, r.UID, dst.Addr)
		}
	}
	return nil
}

// validRemoteAddress requires an address one rule can match and that names a
// host outside the pod: traffic to the pod's own addresses and to loopback is
// permitted by the pod-local rule, not by a policy exception.
func validRemoteAddress(addr netip.Addr) error {
	switch {
	case !addr.IsValid():
		return fmt.Errorf("%w: invalid address", ErrPolicy)
	case addr.Is4In6():
		return fmt.Errorf("%w: 4-in-6 address %s", ErrPolicy, addr)
	case addr.IsUnspecified() || addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%w: address %s matches more than one host", ErrPolicy, addr)
	case addr.IsLoopback() || addr.IsLinkLocalUnicast():
		return fmt.Errorf("%w: address %s is local to a pod", ErrPolicy, addr)
	}
	return nil
}
