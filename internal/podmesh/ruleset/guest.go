//go:build linux

package ruleset

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// GuestPolicy routes one standalone Pod's egress and authenticated ingress.
// The caller installs and verifies the Pod rules before enabling this path.
type GuestPolicy struct {
	Bridge       string
	PodAddress   netip.Addr
	Peers        []Destination
	IngressPorts []uint16
}

func (p GuestPolicy) validate() error {
	if p.Bridge == "" || len(p.Bridge) >= unix.IFNAMSIZ || strings.ContainsAny(p.Bridge, "/\x00") {
		return fmt.Errorf("%w: invalid guest bridge", ErrPolicy)
	}
	if !p.PodAddress.Is4() || validRemoteAddress(p.PodAddress) != nil {
		return fmt.Errorf("%w: invalid guest Pod address", ErrPolicy)
	}
	for _, port := range p.IngressPorts {
		switch port {
		case 0, 8443, 15001, 15006, 15021:
			return fmt.Errorf("%w: reserved guest ingress port %d", ErrPolicy, port)
		}
	}
	return validatePeers(p.Peers)
}

// InstallGuest installs once, or verifies an existing identical installation.
// Existing flows for guest services remain; no Pod container runs before this.
func InstallGuest(netnsPath string, p GuestPolicy) error {
	if err := p.validate(); err != nil {
		return err
	}
	err := inNetNS(netnsPath, func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		tables, err := conn.ListTables()
		if err != nil {
			return err
		}
		if len(tables) != 0 {
			return nil
		}
		if err := requireNoXtablesRules(); err != nil {
			return err
		}
		queueRuleset(conn, buildGuest(p))
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("install guest ruleset: %w", err)
		}
		return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o600)
	})
	if err != nil {
		return err
	}
	// Reuse never repairs an unexpected table or re-enables disabled routing.
	return VerifyGuest(netnsPath, p)
}

// VerifyGuest verifies all guest packet rules and routing before admission.
func VerifyGuest(netnsPath string, p GuestPolicy) error {
	if err := p.validate(); err != nil {
		return err
	}
	if err := verifyRuleset(netnsPath, buildGuest(p)); err != nil {
		return err
	}
	return inNetNS(netnsPath, func() error {
		if _, err := netlink.LinkByName(p.Bridge); err != nil {
			return mismatchf("guest Pod bridge %s: %v", p.Bridge, err)
		}
		value, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(value)) != "1" {
			return mismatchf("guest IPv4 forwarding is disabled")
		}
		return nil
	})
}

func buildGuest(p GuestPolicy) []chain {
	fromPod := slices.Concat(matchInterface(expr.MetaKeyIIFNAME, p.Bridge), matchSource(p.PodAddress))
	toPod := slices.Concat(matchInterface(expr.MetaKeyOIFNAME, p.Bridge), matchDestination(p.PodAddress))
	// Kubelet probes the endpoint; only replies to that guest-initiated flow
	// pass. No Pod-initiated flow reaches a guest-owned address.
	input := chain{name: "guest-input", kind: nftables.ChainTypeFilter, hook: *nftables.ChainHookInput,
		priority: *nftables.ChainPriorityFilter, policy: nftables.ChainPolicyAccept,
		rules: []rule{
			{"probe-replies", withVerdict(slices.Concat(fromPod, matchTCPSourcePort(15021), matchCtState(ctStateEstablished), matchCtReply()), expr.VerdictAccept)},
			{"deny-pod-to-guest", withVerdict(matchInterface(expr.MetaKeyIIFNAME, p.Bridge), expr.VerdictDrop)},
		}}
	forward := denyChain("guest-forward", *nftables.ChainHookForward, []rule{
		{"deny-link-local", withVerdict(slices.Concat(fromPod, matchDestinationRange(netip.MustParsePrefix("169.254.0.0/16"))), expr.VerdictDrop)},
		{"egress-replies", withVerdict(slices.Concat(toPod, matchCtState(ctStateEstablished), matchCtReply()), expr.VerdictAccept)},
		{"egress-icmp-errors", withVerdict(slices.Concat(toPod, matchRelatedICMP(unix.IPPROTO_ICMP)), expr.VerdictAccept)},
		{"ingress-replies", withVerdict(slices.Concat(fromPod, matchCtState(ctStateEstablished), matchCtReply(), matchDNAT()), expr.VerdictAccept)},
	})
	ingress := captureChain("guest-ingress", *nftables.ChainHookPrerouting, []rule{
		{"no-pod-hairpin", withVerdict(matchInterface(expr.MetaKeyIIFNAME, p.Bridge), expr.VerdictReturn)},
	})
	egress := chain{name: "guest-egress", kind: nftables.ChainTypeNAT, hook: *nftables.ChainHookPostrouting,
		priority: *nftables.ChainPriorityNATSource, policy: nftables.ChainPolicyAccept}
	for _, port := range p.IngressPorts {
		name := fmt.Sprintf("ingress-%d", port)
		forward.rules = append(forward.rules, rule{name, withVerdict(slices.Concat(toPod, matchTCPPort(port), matchDNAT()), expr.VerdictAccept)})
		translate := []expr.Any{
			&expr.Immediate{Register: compareRegister, Data: p.PodAddress.AsSlice()},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: compareRegister},
		}
		ingress.rules = append(ingress.rules, rule{name, slices.Concat([]expr.Any{meta(expr.MetaKeyNFPROTO), compare([]byte{unix.NFPROTO_IPV4})}, matchLocalDestination(), matchTCPPort(port), translate)})
	}
	for _, protocol := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		name := fmt.Sprintf("pod-egress-%d", protocol)
		match := slices.Concat(fromPod, matchProtocol(protocol))
		forward.rules = append(forward.rules, rule{name, withVerdict(match, expr.VerdictAccept)})
		egress.rules = append(egress.rules, rule{name, append(slices.Clone(match), &expr.Masq{})})
	}
	return []chain{input, forward, ingress, egress}
}

func matchInterface(key expr.MetaKey, value string) []expr.Any {
	name := make([]byte, unix.IFNAMSIZ)
	copy(name, value)
	return []expr.Any{meta(key), compare(name)}
}

func matchSource(addr netip.Addr) []expr.Any {
	return []expr.Any{meta(expr.MetaKeyNFPROTO), compare([]byte{unix.NFPROTO_IPV4}),
		loadHeader(expr.PayloadBaseNetworkHeader, 12, 4), compare(addr.AsSlice())}
}

func matchCtReply() []expr.Any {
	return []expr.Any{&expr.Ct{Key: expr.CtKeyDIRECTION, Register: compareRegister}, compare([]byte{1})}
}

func matchDNAT() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATUS, Register: compareRegister},
		&expr.Bitwise{SourceRegister: compareRegister, DestRegister: compareRegister, Len: 4, Mask: nativeU32(1 << 5), Xor: nativeU32(0)},
		compare(nativeU32(1 << 5)),
	}
}
