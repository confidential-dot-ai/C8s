// Discovery: the addresses a replica of this cluster may answer at.
//
// The measured configuration names its replicas, by DNS name or by address,
// and each name resolves to the addresses of the replicas behind it, at the
// one port every replica of the cluster serves its peers on. The host
// answers every lookup, so a resolved address is where to look for a replica
// and nothing more: who is there is whatever member answers with its attested
// id (members.go). An entry that does not resolve leaves this replica unable
// to say that a replica is absent, which is what Genesis turns on.

package cdsha

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// resolveEntry answers every address one replica entry names.
type resolveEntry func(ctx context.Context, entry string) ([]netip.AddrPort, error)

// resolveAtPort resolves a replica entry with the system resolver, at the
// port the cluster's replicas serve their peers on. An entry that carries a
// port of its own names no replica.
func resolveAtPort(ctx context.Context, entry string, port uint16) ([]netip.AddrPort, error) {
	if address, err := netip.ParseAddr(entry); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(address, port)}, nil
	}
	if strings.Contains(entry, ":") {
		return nil, fmt.Errorf("replica %q is neither an address nor a name: a replica entry carries no port", entry)
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", entry)
	if err != nil {
		return nil, fmt.Errorf("resolve replica %q: %w", entry, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("replica %q has no IPv4 address", entry)
	}
	answered := make([]netip.AddrPort, 0, len(addresses))
	for _, address := range addresses {
		answered = append(answered, netip.AddrPortFrom(address.Unmap(), port))
	}
	return answered, nil
}

// discovered is what one pass of discovery found.
type discovered struct {
	addresses []netip.AddrPort
	// complete reports a pass that resolved every entry. A pass that did not
	// cannot establish that a replica is absent.
	complete bool
}

// discover is the only place a replica learns of an address to look for a
// peer at.
func (n *Node) discover(ctx context.Context) discovered {
	found := discovered{complete: true}
	for _, entry := range n.cfg.Replicas {
		addresses, err := n.cfg.resolve(ctx, entry)
		if err != nil {
			found.complete = false
			n.discoveryFailed(err)
			continue
		}
		if len(addresses) == 0 {
			found.complete = false
			n.discoveryFailed(fmt.Errorf("replica %q resolves to no address", entry))
			continue
		}
		for _, address := range addresses {
			if !slices.Contains(found.addresses, address) {
				found.addresses = append(found.addresses, address)
			}
		}
	}
	return found
}

// discoveryFailed reports an entry that did not resolve, once per reason.
func (n *Node) discoveryFailed(err error) {
	if n.discoveryLog.changed(err.Error()) {
		slog.Warn("cds-ha: this replica cannot resolve every replica of its cluster", "error", err)
	}
}

// changedReason reports a condition that holds tick after tick once.
type changedReason struct {
	mu   sync.Mutex
	last string
}

func (c *changedReason) changed(reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if reason == c.last {
		return false
	}
	c.last = reason
	return true
}
