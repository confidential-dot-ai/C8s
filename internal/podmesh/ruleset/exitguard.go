//go:build linux

package ruleset

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// guardTableName is the table the node's network namespace keeps exit guards
// in: one chain per pod granted exits, named after that pod's namespace.
const guardTableName = "c8s-exit-guard"

// ctOriginal is IP_CT_DIR_ORIGINAL: the tuple as the pod opened the
// connection, before any translation.
const ctOriginal = 0

// GuardExits installs, in the node network namespace at nodeNetns, the chain
// that drops a connection from the pod at podNetns to one of its exits once the
// node has translated its destination. The pod's ruleset sees only the address
// the application dialed; a Service the control plane publishes on an exit
// address (externalIPs, a load-balancer IP) is translated after the pod, on the
// node, to wherever its endpoints are. An exit is a way out of the cluster, so
// no translation of one is kept, whatever it points to.
//
// The chain runs after destination NAT on the prerouting hook, so it sees a
// flow bound for the node itself as well as one routed on. It sees only the
// translations conntrack records: one made in eBPF, such as Cilium's Service
// load balancing, never reaches the hook. The pod's addresses
// are read from its namespace; the worker's Cilium verifies a pod's source
// address.
// GuardExits replaces the pod's chain in one transaction and verifies it.
func GuardExits(nodeNetns, podNetns string, exits []Exit) error {
	expected, err := guardFor(podNetns, exits)
	if err != nil {
		return err
	}
	err = inNetNS(nodeNetns, func() error {
		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("open nftables: %w", err)
		}
		table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: guardTableName})
		live := conn.AddChain(&nftables.Chain{
			Name:     expected.name,
			Table:    table,
			Type:     expected.kind,
			Hooknum:  &expected.hook,
			Priority: &expected.priority,
			Policy:   &expected.policy,
		})
		conn.FlushChain(live)
		for _, r := range expected.rules {
			conn.AddRule(&nftables.Rule{Table: table, Chain: live, Exprs: r.exprs})
		}
		return conn.Flush()
	})
	if err != nil {
		return fmt.Errorf("install the exit guard: %w", err)
	}
	return VerifyExitGuard(nodeNetns, podNetns, exits)
}

// VerifyExitGuard reports an error unless the node network namespace at
// nodeNetns holds exactly the exit guard GuardExits installs for the pod at
// podNetns and exits. Other tables and other pods' chains are the node's own
// and are left alone: a drop in any base chain is final.
func VerifyExitGuard(nodeNetns, podNetns string, exits []Exit) error {
	expected, err := guardFor(podNetns, exits)
	if err != nil {
		return err
	}
	return inNetNS(nodeNetns, func() error {
		conn, err := nfnl.Dial(unix.NETLINK_NETFILTER, nil)
		if err != nil {
			return fmt.Errorf("dial netfilter netlink: %w", err)
		}
		defer conn.Close()
		if err := requireGuardTable(conn); err != nil {
			return err
		}
		if err := requireGuardChain(conn, expected); err != nil {
			return err
		}
		return requireGuardRules(conn, expected)
	})
}

// ReleaseExitGuard removes the exit guard of the pod whose network namespace
// had inode podNamespace, if the node network namespace at nodeNetns holds one.
func ReleaseExitGuard(nodeNetns string, podNamespace uint64) error {
	return inNetNS(nodeNetns, func() error {
		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("open nftables: %w", err)
		}
		chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
		if err != nil {
			return fmt.Errorf("list nftables chains: %w", err)
		}
		name := guardChainName(podNamespace)
		for _, c := range chains {
			if c.Table.Name == guardTableName && c.Name == name {
				conn.DelChain(c)
				return conn.Flush()
			}
		}
		return nil
	})
}

// ExitGuards lists the namespace inodes of the pods the node network namespace
// at nodeNetns holds an exit guard for.
func ExitGuards(nodeNetns string) ([]uint64, error) {
	var inodes []uint64
	err := inNetNS(nodeNetns, func() error {
		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("open nftables: %w", err)
		}
		chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
		if err != nil {
			return fmt.Errorf("list nftables chains: %w", err)
		}
		for _, c := range chains {
			if c.Table.Name != guardTableName {
				continue
			}
			var inode uint64
			if _, err := fmt.Sscanf(c.Name, guardChainFormat, &inode); err != nil || guardChainName(inode) != c.Name {
				return fmt.Errorf("%w: exit guard table holds chain %q", ErrMismatch, c.Name)
			}
			inodes = append(inodes, inode)
		}
		return nil
	})
	return inodes, err
}

// guardFor is the guard chain of the pod at podNetns with exits.
func guardFor(podNetns string, exits []Exit) (chain, error) {
	if len(exits) == 0 {
		return chain{}, fmt.Errorf("%w: no exits to guard", ErrPolicy)
	}
	for _, exit := range exits {
		if err := exit.validate(); err != nil {
			return chain{}, err
		}
	}
	namespace, err := readNamespaceInode(podNetns)
	if err != nil {
		return chain{}, err
	}
	var sources []netip.Addr
	if err := inNetNS(podNetns, func() error {
		sources, err = podSources()
		return err
	}); err != nil {
		return chain{}, err
	}
	if len(sources) == 0 {
		return chain{}, fmt.Errorf("%w: the pod has no address to guard its exits by", ErrPolicy)
	}
	return buildGuard(namespace, sources, exits), nil
}

func buildGuard(namespace uint64, sources []netip.Addr, exits []Exit) chain {
	var rules []rule
	for _, source := range sources {
		for _, exit := range exits {
			if source.Is4() != exit.Range.Addr().Is4() {
				continue
			}
			exprs := slices.Concat(matchSource(source), matchProtocol(unix.IPPROTO_TCP), matchDNAT(), matchOriginalDestination(exit))
			name := fmt.Sprintf("translated-exit-%s-%d-from-%s", exit.Range, exit.Port, source)
			rules = append(rules, rule{name, withVerdict(exprs, expr.VerdictDrop)})
		}
	}
	return chain{
		name:     guardChainName(namespace),
		kind:     nftables.ChainTypeFilter,
		hook:     *nftables.ChainHookPrerouting,
		priority: *nftables.ChainPriorityFilter,
		policy:   nftables.ChainPolicyAccept,
		rules:    rules,
	}
}

const guardChainFormat = "pod-netns-%d"

func guardChainName(namespace uint64) string {
	return fmt.Sprintf(guardChainFormat, namespace)
}

// podSources are the attached namespace's addresses a routed packet can come
// from, in a fixed order. Loopback never leaves the pod, and the node does not
// route a link-local source on.
func podSources() ([]netip.Addr, error) {
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list the pod's addresses: %w", err)
	}
	var sources []netip.Addr
	for _, address := range addresses {
		addr, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		sources = append(sources, addr)
	}
	slices.SortFunc(sources, netip.Addr.Compare)
	return slices.Compact(sources), nil
}

// matchOriginalDestination matches a connection the pod opened to exit,
// read from its conntrack entry: the packet carries the translated
// destination. The caller pins the family; an IPv4 address fills the first
// bytes of the loaded tuple address.
func matchOriginalDestination(exit Exit) []expr.Any {
	raw := exit.Range.Addr().AsSlice()
	return []expr.Any{
		&expr.Ct{Register: compareRegister, Key: expr.CtKeyDST, Direction: ctOriginal},
		&expr.Bitwise{
			SourceRegister: compareRegister,
			DestRegister:   compareRegister,
			Len:            uint32(len(raw)),
			Mask:           net.CIDRMask(exit.Range.Bits(), len(raw)*8),
			Xor:            make([]byte, len(raw)),
		},
		compare(raw),
		&expr.Ct{Register: compareRegister, Key: expr.CtKeyPROTODST, Direction: ctOriginal},
		compare(networkU16(exit.Port)),
	}
}

// requireGuardTable requires the guard table in the inet family with no flag
// set: a dormant table lists its chains while its hooks are gone.
func requireGuardTable(conn *nfnl.Conn) error {
	tables, err := dumpNFTables(conn, unix.NFT_MSG_GETTABLE)
	if err != nil {
		return err
	}
	for _, message := range tables {
		family, attributes, err := netfilterReply(message)
		if err != nil {
			return err
		}
		var name string
		var flags uint32
		for attributes.Next() {
			switch attributes.Type() {
			case unix.NFTA_TABLE_NAME:
				name = attributes.String()
			case unix.NFTA_TABLE_FLAGS:
				flags = attributes.Uint32()
			}
		}
		if err := attributes.Err(); err != nil {
			return fmt.Errorf("decode table: %w", err)
		}
		if name != guardTableName || family != unix.NFPROTO_INET {
			continue
		}
		if flags != 0 {
			return mismatchf("exit guard table flags %#x", flags)
		}
		return nil
	}
	return mismatchf("exit guard table %s is absent", guardTableName)
}

// requireGuardChain requires the pod's guard chain where the guard expects it.
func requireGuardChain(conn *nfnl.Conn, want chain) error {
	messages, err := dumpNFTables(conn, unix.NFT_MSG_GETCHAIN)
	if err != nil {
		return err
	}
	for _, message := range messages {
		family, table, name, err := chainOwner(message)
		if err != nil {
			return err
		}
		if family != unix.NFPROTO_INET || table != guardTableName || name != want.name {
			continue
		}
		got, err := readChain(message)
		if err != nil {
			return err
		}
		if got.kind != want.kind || got.hook != want.hook || got.priority != want.priority || got.policy != want.policy {
			return mismatchf("exit guard chain %s is %s at hook %d priority %d policy %d", want.name, got.kind, got.hook, got.priority, got.policy)
		}
		return nil
	}
	return mismatchf("exit guard chain %s is absent", want.name)
}

func chainOwner(message nfnl.Message) (byte, string, string, error) {
	family, attributes, err := netfilterReply(message)
	if err != nil {
		return 0, "", "", err
	}
	var table, name string
	for attributes.Next() {
		switch attributes.Type() {
		case unix.NFTA_CHAIN_TABLE:
			table = attributes.String()
		case unix.NFTA_CHAIN_NAME:
			name = attributes.String()
		}
	}
	if err := attributes.Err(); err != nil {
		return 0, "", "", fmt.Errorf("decode chain: %w", err)
	}
	return family, table, name, nil
}

// requireGuardRules requires the pod's guard chain to hold exactly the
// expected rules, in order, compared as the kernel stores them.
func requireGuardRules(conn *nfnl.Conn, want chain) error {
	messages, err := dumpGuardRules(conn, want.name)
	if err != nil {
		return err
	}
	var live [][]byte
	for _, message := range messages {
		family, attributes, err := netfilterReply(message)
		if err != nil {
			return err
		}
		var table, chainName string
		var expressions []byte
		for attributes.Next() {
			switch attributes.Type() {
			case unix.NFTA_RULE_TABLE:
				table = attributes.String()
			case unix.NFTA_RULE_CHAIN:
				chainName = attributes.String()
			case unix.NFTA_RULE_EXPRESSIONS:
				expressions = attributes.Bytes()
			}
		}
		if err := attributes.Err(); err != nil {
			return fmt.Errorf("decode rule: %w", err)
		}
		if family == unix.NFPROTO_INET && table == guardTableName && chainName == want.name {
			live = append(live, expressions)
		}
	}
	if len(live) != len(want.rules) {
		return mismatchf("exit guard chain %s holds %d rules, expected %d", want.name, len(live), len(want.rules))
	}
	for i, wanted := range want.rules {
		marshalled, err := marshalExpressions(wanted)
		if err != nil {
			return err
		}
		if err := compareAttributes(marshalled, live[i]); err != nil {
			return mismatchf("expressions of exit guard chain %s rule %d (%s): %s", want.name, i, wanted.name, err)
		}
	}
	return nil
}

// dumpGuardRules asks for the rules of one guard chain only: the node's own
// tables can hold thousands.
func dumpGuardRules(conn *nfnl.Conn, chainName string) ([]nfnl.Message, error) {
	request := bytes.Buffer{}
	header := unix.Nfgenmsg{Nfgen_family: unix.NFPROTO_INET, Version: unix.NFNETLINK_V0}
	if err := binary.Write(&request, binary.BigEndian, header); err != nil {
		return nil, err
	}
	filter, err := nfnl.MarshalAttributes([]nfnl.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: append([]byte(guardTableName), 0)},
		{Type: unix.NFTA_RULE_CHAIN, Data: append([]byte(chainName), 0)},
	})
	if err != nil {
		return nil, err
	}
	request.Write(filter)
	replies, err := conn.Execute(nfnl.Message{
		Header: nfnl.Header{
			Type:  nfnl.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE),
			Flags: nfnl.Request | nfnl.Dump,
		},
		Data: request.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("dump the exit guard rules: %w", err)
	}
	return replies, nil
}
