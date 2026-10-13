//go:build linux

package ruleset

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// tableName is the pod's only nftables table. Every match of its rules loads
// the value it compares into compareRegister and compares it there, so no rule
// depends on a register another rule left behind.
const (
	tableName       = "c8s-podmesh"
	compareRegister = 1
)

// Conntrack state bits as the kernel reports them in the state register, and
// the ICMPv6 types a pod's own neighbour discovery needs.
const (
	ctStateEstablished     = 1 << 1
	ctStateRelated         = 1 << 2
	neighbourSolicitation  = 135
	neighbourAdvertisement = 136
)

// chain is one base chain; every chain of this ruleset is hooked.
type chain struct {
	name     string
	kind     nftables.ChainType
	hook     nftables.ChainHook
	priority nftables.ChainPriority
	policy   nftables.ChainPolicy
	rules    []rule
}

// rule is one nftables rule. The name labels it in mismatch reports and golden
// expectations; only the expressions are compared against the live ruleset.
type rule struct {
	name  string
	exprs []expr.Any
}

// build returns the chains p defines, in the order they are installed.
func build(p Policy) []chain {
	return []chain{
		captureInbound(p), captureOutbound(p), filterInput(p), filterOutput(p),
		// A member pod routes nothing.
		denyChain("filter-forward", *nftables.ChainHookForward, nil),
	}
}

// captureInbound redirects application TCP arriving at the pod to the inbound
// listener; loopback and the health port stay uncaptured.
func captureInbound(p Policy) chain {
	rules := []rule{
		{"loopback", withVerdict(matchInputLoopback(), expr.VerdictReturn)},
		{"health-port", withVerdict(matchTCPPort(p.Capture.Health), expr.VerdictReturn)},
		{"redirect-to-inbound-listener", redirectTCP(p.Capture.Inbound)},
	}
	return captureChain("capture-inbound", *nftables.ChainHookPrerouting, rules)
}

// captureOutbound redirects application TCP leaving the pod to the outbound
// listener. Pod-local destinations, queries to an approved resolver and
// platform-role sockets stay uncaptured; the resolver port elsewhere is
// captured like every other destination.
func captureOutbound(p Policy) chain {
	rules := []rule{
		{"pod-local", withVerdict(matchLocalDestination(), expr.VerdictReturn)},
		{"mesh-sockets", withVerdict(matchSocketUID(p.MeshUID), expr.VerdictReturn)},
	}
	for _, role := range p.Roles {
		name := fmt.Sprintf("role-%d-sockets", role.UID)
		rules = append(rules, rule{name, withVerdict(matchSocketUID(role.UID), expr.VerdictReturn)})
	}
	resolverTCP := fmt.Sprintf("resolver-%s-tcp", p.Resolver)
	rules = append(rules, rule{resolverTCP, withVerdict(matchResolver(p.Resolver, unix.IPPROTO_TCP), expr.VerdictReturn)})
	rules = append(rules, rule{"redirect-to-outbound-listener", redirectTCP(p.Capture.Outbound)})
	return captureChain("capture-outbound", *nftables.ChainHookOutput, rules)
}

// filterInput denies traffic entering the pod unless it is a reply, loopback,
// neighbour discovery, or addressed to a mesh listener.
func filterInput(p Policy) chain {
	rules := slices.Concat(replyAndControlRules(), []rule{
		{"loopback", withVerdict(matchInputLoopback(), expr.VerdictAccept)},
		{"inbound-listener", withVerdict(matchTCPPort(p.Capture.Inbound), expr.VerdictAccept)},
		{"health-port", withVerdict(matchTCPPort(p.Capture.Health), expr.VerdictAccept)},
	})
	return denyChain("filter-input", *nftables.ChainHookInput, rules)
}

// filterOutput denies traffic leaving the pod unless it is a reply, bound for
// a pod-local address, neighbour discovery, an approved resolver query, or sent
// by a platform role to a destination it is bound to. No member pod process
// runs as root, so a root-owned socket here entered the namespace from
// outside, as port-forward does.
func filterOutput(p Policy) chain {
	resolverUDP := fmt.Sprintf("resolver-%s-udp", p.Resolver)
	resolverTCP := fmt.Sprintf("resolver-%s-tcp", p.Resolver)
	rules := slices.Concat([]rule{
		{"namespace-entrant", withVerdict(matchSocketUID(0), expr.VerdictDrop)},
	}, listenerOwnerRules(p), replyAndControlRules(), []rule{
		{"pod-local", withVerdict(matchLocalDestination(), expr.VerdictAccept)},
		{resolverUDP, withVerdict(matchResolver(p.Resolver, unix.IPPROTO_UDP), expr.VerdictAccept)},
		{resolverTCP, withVerdict(matchResolver(p.Resolver, unix.IPPROTO_TCP), expr.VerdictAccept)},
		{"mesh-sockets", withVerdict(matchSocketUID(p.MeshUID), expr.VerdictAccept)},
	})
	for _, role := range p.Roles {
		rules = append(rules, roleDestinationRules(role)...)
	}
	return denyChain("filter-output", *nftables.ChainHookOutput, rules)
}

// listenerOwnerRules reserve the mesh listeners the input chain admits to the
// mesh endpoint: only its sockets may answer on those ports, so a process that
// takes a listener over once the endpoint is gone exchanges nothing. They
// precede the reply rules, which would otherwise carry the handshake.
func listenerOwnerRules(p Policy) []rule {
	rules := make([]rule, 0, 4)
	for _, port := range []uint16{p.Capture.Inbound, p.Capture.Health} {
		mesh := slices.Concat(matchSocketUID(p.MeshUID), matchTCPSourcePort(port))
		name := fmt.Sprintf("mesh-listener-%d", port)
		rules = append(rules, rule{name, withVerdict(mesh, expr.VerdictAccept)})
		taken := fmt.Sprintf("listener-%d-taken-over", port)
		rules = append(rules, rule{taken, withVerdict(matchTCPSourcePort(port), expr.VerdictDrop)})
	}
	return rules
}

func captureChain(name string, hook nftables.ChainHook, rules []rule) chain {
	return chain{
		name:     name,
		kind:     nftables.ChainTypeNAT,
		hook:     hook,
		priority: *nftables.ChainPriorityNATDest,
		policy:   nftables.ChainPolicyAccept,
		rules:    rules,
	}
}

func denyChain(name string, hook nftables.ChainHook, rules []rule) chain {
	return chain{
		name:     name,
		kind:     nftables.ChainTypeFilter,
		hook:     hook,
		priority: *nftables.ChainPriorityFilter,
		policy:   nftables.ChainPolicyDrop,
		rules:    rules,
	}
}

// roleDestinationRules permit a role's sockets the services trusted policy
// bound to it.
func roleDestinationRules(role Role) []rule {
	rules := make([]rule, 0, len(role.Destinations))
	for _, dst := range role.Destinations {
		exprs := slices.Concat(matchSocketUID(role.UID), matchDestination(dst.Addr), matchTCPPort(dst.Port))
		name := fmt.Sprintf("role-%d-destination-%s-%d", role.UID, dst.Addr, dst.Port)
		rules = append(rules, rule{name, withVerdict(exprs, expr.VerdictAccept)})
	}
	return rules
}

// replyAndControlRules permit the replies of an admitted connection, its ICMP
// errors and the neighbour discovery the pod's own addresses need. Related
// traffic is confined to ICMP, so no conntrack helper opens a data path.
func replyAndControlRules() []rule {
	return []rule{
		{"replies", withVerdict(matchCtState(ctStateEstablished), expr.VerdictAccept)},
		{"icmp-errors", withVerdict(matchRelatedICMP(unix.IPPROTO_ICMP), expr.VerdictAccept)},
		{"icmpv6-errors", withVerdict(matchRelatedICMP(unix.IPPROTO_ICMPV6), expr.VerdictAccept)},
		{"neighbour-solicitation", withVerdict(matchICMPv6Type(neighbourSolicitation), expr.VerdictAccept)},
		{"neighbour-advertisement", withVerdict(matchICMPv6Type(neighbourAdvertisement), expr.VerdictAccept)},
	}
}

func withVerdict(exprs []expr.Any, kind expr.VerdictKind) []expr.Any {
	return append(exprs, &expr.Verdict{Kind: kind})
}

func matchSocketUID(uid uint32) []expr.Any {
	return []expr.Any{meta(expr.MetaKeySKUID), compare(nativeU32(uid))}
}

func matchInputLoopback() []expr.Any {
	name := make([]byte, unix.IFNAMSIZ) // the kernel compares a fixed-width name
	copy(name, "lo")
	return []expr.Any{meta(expr.MetaKeyIIFNAME), compare(name)}
}

// matchLocalDestination matches the pod's own addresses and loopback, which
// carry plaintext inside the pod and to the mesh listeners.
func matchLocalDestination() []expr.Any {
	return []expr.Any{
		&expr.Fib{
			Register:       compareRegister,
			ResultADDRTYPE: true,
			FlagDADDR:      true,
		},
		compare(nativeU32(unix.RTN_LOCAL)),
	}
}

func matchResolver(addr netip.Addr, proto uint8) []expr.Any {
	return slices.Concat(matchDestination(addr), matchProtocol(proto), matchTransportDestinationPort(resolverPort))
}

// matchDestination pins an address to its family, so an IPv4 rule cannot
// match an IPv6 header.
func matchDestination(addr netip.Addr) []expr.Any {
	family := uint8(unix.NFPROTO_IPV4)
	offset := uint32(16)
	if addr.Is6() {
		family = unix.NFPROTO_IPV6
		offset = 24
	}
	raw := addr.AsSlice()
	return []expr.Any{
		meta(expr.MetaKeyNFPROTO), compare([]byte{family}),
		loadHeader(expr.PayloadBaseNetworkHeader, offset, uint32(len(raw))), compare(raw),
	}
}

func matchTCPPort(port uint16) []expr.Any {
	return slices.Concat(matchProtocol(unix.IPPROTO_TCP), matchTransportDestinationPort(port))
}

func matchTCPSourcePort(port uint16) []expr.Any {
	return slices.Concat(matchProtocol(unix.IPPROTO_TCP), matchTransportSourcePort(port))
}

func matchProtocol(proto uint8) []expr.Any {
	return []expr.Any{meta(expr.MetaKeyL4PROTO), compare([]byte{proto})}
}

func matchTransportDestinationPort(port uint16) []expr.Any {
	return []expr.Any{loadHeader(expr.PayloadBaseTransportHeader, 2, 2), compare(networkU16(port))}
}

func matchTransportSourcePort(port uint16) []expr.Any {
	return []expr.Any{loadHeader(expr.PayloadBaseTransportHeader, 0, 2), compare(networkU16(port))}
}

func matchCtState(state uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Register: compareRegister,
			Key:      expr.CtKeySTATE,
		},
		&expr.Bitwise{
			SourceRegister: compareRegister,
			DestRegister:   compareRegister,
			Len:            4,
			Mask:           nativeU32(state),
			Xor:            nativeU32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: compareRegister,
			Data:     nativeU32(0),
		},
	}
}

func matchRelatedICMP(proto uint8) []expr.Any {
	return slices.Concat(matchCtState(ctStateRelated), matchProtocol(proto))
}

func matchICMPv6Type(messageType uint8) []expr.Any {
	return slices.Concat(matchProtocol(unix.IPPROTO_ICMPV6),
		[]expr.Any{loadHeader(expr.PayloadBaseTransportHeader, 0, 1), compare([]byte{messageType})})
}

// redirectTCP sends a connection to a mesh listener of the pod, leaving its
// original destination in the namespace's conntrack entry.
func redirectTCP(port uint16) []expr.Any {
	return append(matchProtocol(unix.IPPROTO_TCP),
		&expr.Immediate{
			Register: compareRegister,
			Data:     networkU16(port),
		},
		&expr.Redir{
			RegisterProtoMin: compareRegister,
			RegisterProtoMax: compareRegister,
			Flags:            unix.NF_NAT_RANGE_PROTO_SPECIFIED,
		},
	)
}

func meta(key expr.MetaKey) expr.Any {
	return &expr.Meta{
		Key:      key,
		Register: compareRegister,
	}
}

func compare(data []byte) expr.Any {
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: compareRegister,
		Data:     data,
	}
}

func loadHeader(base expr.PayloadBase, offset, length uint32) expr.Any {
	return &expr.Payload{
		OperationType: expr.PayloadLoad,
		DestRegister:  compareRegister,
		Base:          base,
		Offset:        offset,
		Len:           length,
	}
}

func nativeU32(value uint32) []byte {
	return binaryutil.NativeEndian.PutUint32(value)
}

func networkU16(value uint16) []byte {
	return binaryutil.BigEndian.PutUint16(value)
}
