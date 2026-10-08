package workloadclaims

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func nodeWith(name string, podCIDRs []string, addrs ...corev1.NodeAddress) *corev1.Node {
	n := &corev1.Node{}
	n.Name = name
	n.Spec.PodCIDRs = podCIDRs
	n.Status.Addresses = addrs
	return n
}

func internalIP(ip string) corev1.NodeAddress {
	return corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: ip}
}

func TestNodeHostCIDRs(t *testing.T) {
	t.Run("one host route per InternalIP, deduplicated", func(t *testing.T) {
		hosts, excluded := NodeHostCIDRs([]*corev1.Node{
			nodeWith("a", nil,
				corev1.NodeAddress{Type: corev1.NodeHostName, Address: "a"},
				internalIP("10.0.1.4"),
				corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: "203.0.113.7"},
				internalIP("fd00::4")),
			nodeWith("b", nil, internalIP("10.0.1.5"), internalIP("10.0.1.5")),
		})
		if len(excluded) != 0 {
			t.Fatalf("excluded = %v, want none", excluded)
		}
		var got []string
		for _, h := range hosts {
			got = append(got, h.String())
		}
		want := []string{"10.0.1.4/32", "fd00::4/128", "10.0.1.5/32"}
		if len(got) != len(want) {
			t.Fatalf("cidrs = %v, want %v (InternalIP only, as host routes)", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("cidrs = %v, want %v", got, want)
			}
		}
	})

	t.Run("non-routable addresses are skipped", func(t *testing.T) {
		hosts, _ := NodeHostCIDRs([]*corev1.Node{
			nodeWith("a", nil, internalIP("127.0.0.1"), internalIP("fe80::1"), internalIP("not-an-ip")),
		})
		if len(hosts) != 0 {
			t.Fatalf("hosts = %v, want none routable", hosts)
		}
	})

	// The security property: a node address inside the pod range cannot be
	// told apart from a pod, so it must never enter the bound — while other
	// nodes stay covered.
	t.Run("node address inside the pod range is excluded, not admitted", func(t *testing.T) {
		hosts, excluded := NodeHostCIDRs([]*corev1.Node{
			nodeWith("a", []string{"10.0.1.0/24"}, internalIP("10.0.1.4")),
			nodeWith("b", []string{"10.0.2.0/24"}, internalIP("192.168.1.5")),
		})
		if len(hosts) != 1 || hosts[0].String() != "192.168.1.5/32" {
			t.Fatalf("hosts = %v, want only node b's address", hosts)
		}
		if len(excluded) != 1 || excluded[0] != "a/10.0.1.4" {
			t.Fatalf("excluded = %v, want a/10.0.1.4 reported", excluded)
		}
	})

	// A CNI that owns IPAM leaves podCIDR empty; the separability check does
	// not run and the node is admitted.
	t.Run("empty podCIDR skips the check", func(t *testing.T) {
		hosts, excluded := NodeHostCIDRs([]*corev1.Node{
			nodeWith("a", nil, internalIP("10.0.1.4")),
		})
		if len(hosts) != 1 || len(excluded) != 0 {
			t.Fatalf("hosts = %v excluded = %v, want the node admitted", hosts, excluded)
		}
	})
}

// NodeHosts is the runtime bound CDS applies per issuance: it must fail
// closed before the informer's first sync, and track the node list in both
// directions — a node added later becomes dialable, a removed node stops
// being dialable. The static snapshot did neither.
func TestNodeHostsTracksTheNodeList(t *testing.T) {
	h := &NodeHosts{}
	if !h.Empty() || h.Contains("10.0.1.4") {
		t.Fatal("before the first sync the bound must be empty and refuse everything")
	}

	h.SetNodes([]*corev1.Node{nodeWith("a", nil, internalIP("10.0.1.4"))})
	if h.Empty() || !h.Contains("10.0.1.4") {
		t.Fatal("node a's address not admitted after sync")
	}
	if h.Contains("10.244.1.5") {
		t.Fatal("a pod-range address was admitted")
	}

	// Scale-up: the new node is covered without a restart.
	h.SetNodes([]*corev1.Node{
		nodeWith("a", nil, internalIP("10.0.1.4")),
		nodeWith("b", nil, internalIP("10.0.1.5")),
	})
	if !h.Contains("10.0.1.5") {
		t.Fatal("a node added later was not admitted")
	}

	// Scale-down/replacement: the gone node's address leaves the bound.
	h.SetNodes([]*corev1.Node{nodeWith("b", nil, internalIP("10.0.1.5"))})
	if h.Contains("10.0.1.4") {
		t.Fatal("a removed node's address stayed dialable")
	}
}

func TestNodeHostsGroupsAddressesByNode(t *testing.T) {
	var h NodeHosts
	h.SetNodes([]*corev1.Node{
		nodeWith("a", nil,
			corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "fec0::1"}),
		nodeWith("b", nil, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "10.0.0.2"}),
	})
	got := h.Nodes()
	if len(got) != 2 || len(got[0]) != 2 || got[1][0] != "10.0.0.2" {
		t.Fatalf("Nodes() = %v, want [[10.0.0.1 fec0::1] [10.0.0.2]]", got)
	}
}
