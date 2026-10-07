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
)

// resolverPort is the only destination port the resolver exception permits.
const resolverPort = 53

// ErrPolicy reports trusted policy no ruleset can be built from.
var ErrPolicy = errors.New("pod ruleset policy")

// Policy is the trusted input the ruleset is built from.
type Policy struct {
	// Resolvers may be reached on the resolver port, over UDP and TCP.
	Resolvers []netip.Addr
	Capture   CapturePorts
	// MeshUID owns sockets that are neither captured nor confined to a
	// destination: the mesh endpoint authenticates its own peers.
	MeshUID uint32
	Roles   []Role
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
	if len(p.Resolvers) == 0 {
		return fmt.Errorf("%w: no resolver address", ErrPolicy)
	}
	for _, addr := range p.Resolvers {
		if err := validRemoteAddress(addr); err != nil {
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
	case addr.IsUnspecified() || addr.IsMulticast():
		return fmt.Errorf("%w: address %s matches more than one host", ErrPolicy, addr)
	case addr.IsLoopback() || addr.IsLinkLocalUnicast():
		return fmt.Errorf("%w: address %s is local to a pod", ErrPolicy, addr)
	}
	return nil
}
