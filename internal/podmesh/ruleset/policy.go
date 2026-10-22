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
// policy names, and the destinations each platform role is bound to.
package ruleset

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
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
	// Server is the platform role whose own ports this pod serves, where the
	// caller builds it for a pod of the router's namespace. Its application
	// traffic is captured like a workload's, and only its external listener
	// ports and its egress identity's ports pass the pod boundary in the
	// clear.
	Server ServerRole
	// Pod restricts a standalone Pod to signed peer tuples, with no node-role
	// or resolver exceptions. Nil preserves the cluster member policy.
	Pod *PodPolicy
}

type PodPolicy struct {
	Peers []Destination
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
	// clear, each one address and port: its own node's CDS, which it fetches
	// the signed route manifest from.
	Services []Destination
	// ClusterRanges are this cluster's pod and Service ranges: the egress
	// exception excludes them, and the upstream identity reaches them
	// uncaptured.
	ClusterRanges []netip.Prefix
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

// CapturePorts are the ports the mesh endpoint listens on in its pod.
type CapturePorts struct {
	Outbound uint16
	Inbound  uint16
	Health   uint16
}

// Role is one platform role bound to a reserved UID, with the services that
// role's containers may reach outside the mesh listeners.
type Role struct {
	UID          uint32
	Destinations []Destination
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
	if p.Pod == nil {
		if err := validRemoteAddress(p.Resolver); err != nil {
			return err
		}
	} else {
		if len(p.Roles) != 0 || !reflect.DeepEqual(p.Server, ServerRole{}) {
			return fmt.Errorf("%w: standalone Pod has platform-role exceptions", ErrPolicy)
		}
		if err := validatePeers(p.Pod.Peers); err != nil {
			return err
		}
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
	}
	return p.Server.validate()
}

func validatePeers(peers []Destination) error {
	values := make([]string, len(peers))
	for i, peer := range peers {
		values[i] = netip.AddrPortFrom(peer.Addr, peer.Port).String()
	}
	if _, err := podmesh.ParseMeshPeers(values); err != nil {
		return fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	return nil
}

// validate rejects a server role no ruleset can carry. Its identities and its
// ports are compiled in (internal/cmds/nri-image-policy), so the cluster
// ranges its egress exception excludes are the one input left: an exception
// that excludes none would carry a forwarded connection to a member out of
// the pod in the clear.
func (s ServerRole) validate() error {
	if !s.serves() {
		return nil
	}
	if s.Upstream == 0 {
		return fmt.Errorf("%w: server role has no upstream identity, so its uncaptured cluster rules would match root", ErrPolicy)
	}
	if len(s.Egress.Ports) > 0 && len(s.ClusterRanges) == 0 {
		return fmt.Errorf("%w: server role UID %d has egress ports and no cluster ranges to exclude from them", ErrPolicy, s.Egress.UID)
	}
	for _, dst := range s.Services {
		if err := validRemoteAddress(dst.Addr); err != nil {
			return err
		}
		if dst.Port == 0 {
			return fmt.Errorf("%w: upstream identity %d service %s has no port", ErrPolicy, s.Upstream, dst.Addr)
		}
	}
	for _, in := range s.ClusterRanges {
		if err := validClusterRange(in); err != nil {
			return err
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
	if len(r.Destinations) == 0 {
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
