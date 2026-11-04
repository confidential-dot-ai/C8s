package cdsha

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"testing"
)

// The cluster's replica entries resolve to every address answering for them:
// one name may stand for several replicas, and an entry that is an address is
// its own answer.
func TestDiscoveryResolvesEveryAddressOfEveryEntry(t *testing.T) {
	behind := map[string][]netip.AddrPort{
		"one.cds.test": {
			netip.MustParseAddrPort("10.0.0.1:8444"),
			netip.MustParseAddrPort("10.0.0.2:8444"),
		},
		"two.cds.test": {netip.MustParseAddrPort("10.0.0.3:8444")},
		"10.0.0.4":     {netip.MustParseAddrPort("10.0.0.4:8444")},
	}
	node := discoveringNode(t, slices.Sorted(maps.Keys(behind)), func(_ context.Context, entry string) ([]netip.AddrPort, error) {
		return behind[entry], nil
	})

	found := node.discover(t.Context())

	if !found.complete {
		t.Fatal("every entry answered and discovery is incomplete")
	}
	want := slices.Concat(behind["one.cds.test"], behind["two.cds.test"], behind["10.0.0.4"])
	found.addresses = sortedAddresses(found.addresses)
	if !slices.Equal(found.addresses, sortedAddresses(want)) {
		t.Fatalf("discovery found %v, want %v", found.addresses, want)
	}
}

// An entry that answers with nothing, or not at all, leaves discovery unable
// to say that a replica is absent.
func TestDiscoveryIsIncompleteWhileAnEntryDoesNotAnswer(t *testing.T) {
	answered := netip.MustParseAddrPort("10.0.0.1:8444")
	for name, resolve := range map[string]resolveEntry{
		"an entry that fails": func(context.Context, string) ([]netip.AddrPort, error) {
			return nil, errors.New("the resolver answered SERVFAIL")
		},
		"an entry that answers with no address": func(context.Context, string) ([]netip.AddrPort, error) {
			return nil, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			node := discoveringNode(t, []string{"one.cds.test", "two.cds.test"}, func(ctx context.Context, entry string) ([]netip.AddrPort, error) {
				if entry == "two.cds.test" {
					return resolve(ctx, entry)
				}
				return []netip.AddrPort{answered}, nil
			})

			found := node.discover(t.Context())

			if found.complete {
				t.Fatal("discovery is complete and one entry did not answer")
			}
			if !slices.Equal(found.addresses, []netip.AddrPort{answered}) {
				t.Fatalf("discovery found %v, want the one address that answered", found.addresses)
			}
		})
	}
}

// An entry that is an IPv4 address is its own answer, at the port every
// replica of the cluster serves its peers on. An entry that carries a port of
// its own names no replica.
func TestAnAddressEntryResolvesToThePeerPort(t *testing.T) {
	addresses, err := resolveAtPort(t.Context(), "10.0.0.7", 8444)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addresses, []netip.AddrPort{netip.MustParseAddrPort("10.0.0.7:8444")}) {
		t.Fatalf("the entry resolved to %v", addresses)
	}
	if _, err := resolveAtPort(t.Context(), "one.cds.test:8444", 8444); err == nil {
		t.Fatal("an entry carrying a port resolved")
	}
}

// discoveringNode is a replica that resolves entries and does nothing else.
func discoveringNode(t *testing.T, entries []string, resolve resolveEntry) *Node {
	t.Helper()
	c := newLiveCluster(t)
	cfg := c.replicaConfig(c.attestationAPI())
	cfg.Replicas = entries
	cfg.Resolve = resolve
	node, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func sortedAddresses(addresses []netip.AddrPort) []netip.AddrPort {
	return slices.SortedFunc(slices.Values(addresses), netip.AddrPort.Compare)
}
