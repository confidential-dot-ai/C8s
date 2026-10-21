//go:build linux

package ruleset

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ErrMismatch reports a pod network namespace whose protection is not the one
// trusted policy defines.
var ErrMismatch = errors.New("pod ruleset mismatch")

// nfgenmsgSize is the netfilter header the kernel puts before its attributes.
var nfgenmsgSize = binary.Size(unix.Nfgenmsg{})

// nftaBitwiseOp is NFTA_BITWISE_OP of nf_tables.h and bitwiseBoolean its
// mask-and-xor operation.
const (
	nftaBitwiseOp  = 0x6
	bitwiseBoolean = 0
)

// dumpNames label the nftables dumps in failures.
var dumpNames = map[uint16]string{
	unix.NFT_MSG_GETTABLE:     "tables",
	unix.NFT_MSG_GETCHAIN:     "chains",
	unix.NFT_MSG_GETRULE:      "rules",
	unix.NFT_MSG_GETSET:       "sets",
	unix.NFT_MSG_GETOBJ:       "objects",
	unix.NFT_MSG_GETFLOWTABLE: "flowtables",
}

// mismatchf reports what differs from the ruleset trusted policy defines.
func mismatchf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMismatch, fmt.Sprintf(format, args...))
}

// Verify reports an error unless the pod network namespace at netnsPath is
// protected by exactly the ruleset Policy defines and nothing else there can
// carry packets past it. The checks run from the ruleset outwards: the pod
// table, its chains and rules, then the hooks that could bypass them. Rules
// are compared as the kernel stores them, attribute by attribute.
func Verify(netnsPath string, p Policy) error {
	if err := p.validate(); err != nil {
		return err
	}
	expected := build(p)
	namespace, err := readNamespaceInode(netnsPath)
	if err != nil {
		return err
	}
	return inNetNS(netnsPath, func() error {
		conn, err := nfnl.Dial(unix.NETLINK_NETFILTER, nil)
		if err != nil {
			return fmt.Errorf("dial netfilter netlink: %w", err)
		}
		defer conn.Close()
		if err := requireOnlyPodTable(conn); err != nil {
			return err
		}
		if err := requireNoNamedState(conn); err != nil {
			return err
		}
		if err := requireChains(conn, expected); err != nil {
			return err
		}
		if err := requireRules(conn, expected); err != nil {
			return err
		}
		if err := requireNoXtablesRules(); err != nil {
			return mismatchf("legacy x_tables rules: %s", err)
		}
		if err := requireNoPacketHooks(); err != nil {
			return err
		}
		pod, err := readPodNetwork(namespace)
		if err != nil {
			return err
		}
		return requireNoPacketBPFLinks(pod)
	})
}

// readNamespaceInode identifies the namespace through the handle the caller
// named: the same path read from inside names the reading thread's own.
func readNamespaceInode(netnsPath string) (uint64, error) {
	handle, err := os.Open(netnsPath)
	if err != nil {
		return 0, fmt.Errorf("open network namespace %s: %w", netnsPath, err)
	}
	defer handle.Close()
	var described unix.Stat_t
	if err := unix.Fstat(int(handle.Fd()), &described); err != nil {
		return 0, fmt.Errorf("describe network namespace %s: %w", netnsPath, err)
	}
	return described.Ino, nil
}

// requireOnlyPodTable requires the pod table, in its family, with no flag
// set: a dormant table lists its chains and rules while its hooks are gone.
func requireOnlyPodTable(conn *nfnl.Conn) error {
	tables, err := dumpNFTables(conn, unix.NFT_MSG_GETTABLE)
	if err != nil {
		return err
	}
	if len(tables) != 1 {
		return mismatchf("%d tables in the namespace", len(tables))
	}
	family, attributes, err := netfilterReply(tables[0])
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
	if name != tableName || family != unix.NFPROTO_INET {
		return mismatchf("table %q in family %d", name, family)
	}
	if flags != 0 {
		return mismatchf("pod table flags %#x", flags)
	}
	return nil
}

// requireNoNamedState requires no set, stateful object or flowtable: the
// ruleset uses none, and a flowtable diverts flows past the hooks.
func requireNoNamedState(conn *nfnl.Conn) error {
	named := 0
	for _, kind := range []uint16{unix.NFT_MSG_GETSET, unix.NFT_MSG_GETOBJ, unix.NFT_MSG_GETFLOWTABLE} {
		found, err := dumpNFTables(conn, kind)
		if err != nil {
			return err
		}
		named += len(found)
	}
	if named > 0 {
		return mismatchf("%d sets, objects or flowtables", named)
	}
	return nil
}

// requireChains requires the expected base chains and nothing else, each
// registered where the ruleset expects: a chain registered earlier sees pod
// traffic first.
func requireChains(conn *nfnl.Conn, expected []chain) error {
	messages, err := dumpNFTables(conn, unix.NFT_MSG_GETCHAIN)
	if err != nil {
		return err
	}
	live := map[string]chain{}
	for _, message := range messages {
		read, err := readChain(message)
		if err != nil {
			return err
		}
		if _, repeated := live[read.name]; repeated {
			return mismatchf("chain %s twice", read.name)
		}
		live[read.name] = read
	}
	for _, want := range expected {
		got, ok := live[want.name]
		if !ok {
			return mismatchf("chain %s is absent", want.name)
		}
		if got.kind != want.kind || got.hook != want.hook || got.priority != want.priority || got.policy != want.policy {
			return mismatchf("chain %s is %s at hook %d priority %d policy %d", want.name, got.kind, got.hook, got.priority, got.policy)
		}
		delete(live, want.name)
	}
	for name := range live {
		return mismatchf("chain %s is not expected", name)
	}
	return nil
}

// readChain decodes one chain of the dump. Handles and counters are kernel
// bookkeeping, not policy.
func readChain(message nfnl.Message) (chain, error) {
	_, attributes, err := netfilterReply(message)
	if err != nil {
		return chain{}, err
	}
	read := chain{}
	hooked := false
	for attributes.Next() {
		switch attributes.Type() {
		case unix.NFTA_CHAIN_NAME:
			read.name = attributes.String()
		case unix.NFTA_CHAIN_TYPE:
			read.kind = nftables.ChainType(attributes.String())
		case unix.NFTA_CHAIN_POLICY:
			read.policy = nftables.ChainPolicy(attributes.Uint32())
		case unix.NFTA_CHAIN_HOOK:
			hooked = true
			attributes.Nested(func(hook *nfnl.AttributeDecoder) error {
				for hook.Next() {
					switch hook.Type() {
					case unix.NFTA_HOOK_HOOKNUM:
						read.hook = nftables.ChainHook(hook.Uint32())
					case unix.NFTA_HOOK_PRIORITY:
						read.priority = nftables.ChainPriority(hook.Int32())
					}
				}
				return hook.Err()
			})
		}
	}
	if err := attributes.Err(); err != nil {
		return chain{}, fmt.Errorf("decode chain: %w", err)
	}
	if !hooked {
		return chain{}, mismatchf("chain %s is not hooked", read.name)
	}
	return read, nil
}

// requireRules requires every chain to hold the expected rules, in the order
// the kernel dumps and evaluates them, with the expected expressions. A rule
// in another chain or table is refused.
func requireRules(conn *nfnl.Conn, expected []chain) error {
	messages, err := dumpNFTables(conn, unix.NFT_MSG_GETRULE)
	if err != nil {
		return err
	}
	live := map[string][][]byte{}
	for _, message := range messages {
		_, attributes, err := netfilterReply(message)
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
		if table != tableName {
			return mismatchf("rule in table %q", table)
		}
		live[chainName] = append(live[chainName], expressions)
	}
	for _, want := range expected {
		if len(live[want.name]) != len(want.rules) {
			return mismatchf("chain %s holds %d rules, expected %d", want.name, len(live[want.name]), len(want.rules))
		}
		for i, wanted := range want.rules {
			marshalled, err := marshalExpressions(wanted)
			if err != nil {
				return err
			}
			if err := compareAttributes(marshalled, live[want.name][i]); err != nil {
				return mismatchf("expressions of chain %s rule %d (%s): %s", want.name, i, wanted.name, err)
			}
		}
		delete(live, want.name)
	}
	for name := range live {
		return mismatchf("rules in chain %s, which is not expected", name)
	}
	return nil
}

// marshalExpressions encodes a rule the way the kernel stores it, so the
// comparison needs no decoder for what comes back.
func marshalExpressions(r rule) ([]byte, error) {
	elements := make([]nfnl.Attribute, 0, len(r.exprs))
	for _, e := range r.exprs {
		var encoded []byte
		var err error
		if bitwise, isBitwise := e.(*expr.Bitwise); isBitwise {
			encoded, err = marshalBitwise(bitwise)
		} else {
			encoded, err = expr.Marshal(byte(nftables.TableFamilyINet), e)
		}
		if err != nil {
			return nil, fmt.Errorf("marshal expressions of rule %s: %w", r.name, err)
		}
		elements = append(elements, nfnl.Attribute{
			Type: unix.NFTA_LIST_ELEM | unix.NLA_F_NESTED,
			Data: encoded,
		})
	}
	return nfnl.MarshalAttributes(elements)
}

// marshalBitwise encodes a mask and xor with the boolean operation the kernel
// reports and the library leaves implicit.
func marshalBitwise(bitwise *expr.Bitwise) ([]byte, error) {
	mask, err := nfnl.MarshalAttributes([]nfnl.Attribute{
		{
			Type: unix.NFTA_DATA_VALUE,
			Data: bitwise.Mask,
		},
	})
	if err != nil {
		return nil, err
	}
	xor, err := nfnl.MarshalAttributes([]nfnl.Attribute{
		{
			Type: unix.NFTA_DATA_VALUE,
			Data: bitwise.Xor,
		},
	})
	if err != nil {
		return nil, err
	}
	fields, err := nfnl.MarshalAttributes([]nfnl.Attribute{
		{
			Type: unix.NFTA_BITWISE_SREG,
			Data: binaryutil.BigEndian.PutUint32(bitwise.SourceRegister),
		},
		{
			Type: unix.NFTA_BITWISE_DREG,
			Data: binaryutil.BigEndian.PutUint32(bitwise.DestRegister),
		},
		{
			Type: unix.NFTA_BITWISE_LEN,
			Data: binaryutil.BigEndian.PutUint32(bitwise.Len),
		},
		{
			Type: unix.NFTA_BITWISE_MASK | unix.NLA_F_NESTED,
			Data: mask,
		},
		{
			Type: unix.NFTA_BITWISE_XOR | unix.NLA_F_NESTED,
			Data: xor,
		},
		{
			Type: nftaBitwiseOp,
			Data: binaryutil.BigEndian.PutUint32(bitwiseBoolean),
		},
	})
	if err != nil {
		return nil, err
	}
	return nfnl.MarshalAttributes([]nfnl.Attribute{
		{
			Type: unix.NFTA_EXPR_NAME,
			Data: []byte("bitwise\x00"),
		},
		{
			Type: unix.NFTA_EXPR_DATA | unix.NLA_F_NESTED,
			Data: fields,
		},
	})
}

// compareAttributes compares two attribute trees: an attribute the kernel
// added, dropped or changed is a difference, recognised by a decoder or not.
// Attributes match by type, repeats of one type in the order they appear,
// because the kernel may reorder distinct attributes but not list elements.
func compareAttributes(expected, live []byte) error {
	want, err := decodeNFTAttributes(expected)
	if err != nil {
		return fmt.Errorf("decode expected attributes: %w", err)
	}
	got, err := decodeNFTAttributes(live)
	if err != nil {
		return fmt.Errorf("decode live attributes: %w", err)
	}
	for kind := range got {
		if _, isExpected := want[kind]; !isExpected {
			return fmt.Errorf("attribute %d is not expected here", kind)
		}
	}
	for kind, wanted := range want {
		if len(got[kind]) != len(wanted) {
			return fmt.Errorf("attribute %d appears %d times, expected %d", kind, len(got[kind]), len(wanted))
		}
		// The kernel omits the nested flag its own encoder sets, so a tree is
		// compared as a tree when either side says so, and the live payload
		// then has to read as one.
		for i, value := range wanted {
			live := got[kind][i]
			switch {
			case live.nested && !value.nested:
				return fmt.Errorf("attribute %d is a tree where a value was expected", kind)
			case value.nested || live.nested:
				if err := compareAttributes(value.data, live.data); err != nil {
					return err
				}
			case !bytes.Equal(value.data, live.data):
				return fmt.Errorf("attribute %d reads %x, expected %x", kind, live.data, value.data)
			}
		}
	}
	return nil
}

// attribute is one attribute's payload and whether a tree continues inside.
type attribute struct {
	nested bool
	data   []byte
}

func decodeNFTAttributes(raw []byte) (map[uint16][]attribute, error) {
	decoder, err := nfnl.NewAttributeDecoder(raw)
	if err != nil {
		return nil, err
	}
	decoder.ByteOrder = binary.BigEndian
	decoded := map[uint16][]attribute{}
	for decoder.Next() {
		kind := decoder.Type() // without the flags, which the kernel leaves out
		decoded[kind] = append(decoded[kind], attribute{
			nested: decoder.TypeFlags()&unix.NLA_F_NESTED != 0,
			data:   decoder.Bytes(),
		})
	}
	return decoded, decoder.Err()
}

// netfilterReply splits one reply into the family it concerns and its
// attributes, refusing a reply too short to hold the netfilter header.
func netfilterReply(message nfnl.Message) (byte, *nfnl.AttributeDecoder, error) {
	if len(message.Data) < nfgenmsgSize {
		return 0, nil, fmt.Errorf("netfilter reply of %d bytes", len(message.Data))
	}
	var header unix.Nfgenmsg
	if err := binary.Read(bytes.NewReader(message.Data), binary.BigEndian, &header); err != nil {
		return 0, nil, fmt.Errorf("decode the netfilter header: %w", err)
	}
	decoder, err := nfnl.NewAttributeDecoder(message.Data[nfgenmsgSize:])
	if err != nil {
		return 0, nil, fmt.Errorf("decode netfilter attributes: %w", err)
	}
	decoder.ByteOrder = binary.BigEndian
	return header.Nfgen_family, decoder, nil
}

// dumpNFTables asks for every object of one kind in the attached namespace,
// in every family, so a table outside the pod's own shows up too.
func dumpNFTables(conn *nfnl.Conn, message uint16) ([]nfnl.Message, error) {
	request := bytes.Buffer{}
	header := unix.Nfgenmsg{
		Nfgen_family: unix.NFPROTO_UNSPEC,
		Version:      unix.NFNETLINK_V0,
	}
	if err := binary.Write(&request, binary.BigEndian, header); err != nil {
		return nil, err
	}
	replies, err := conn.Execute(nfnl.Message{
		Header: nfnl.Header{
			Type:  nfnl.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | message),
			Flags: nfnl.Request | nfnl.Dump,
		},
		Data: request.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("dump nftables %s: %w", dumpNames[message], err)
	}
	return replies, nil
}

// requireNoPacketHooks rejects tc filters on any parent and XDP programs on
// the pod's links: either carries or copies a packet without passing the
// nftables hooks.
func requireNoPacketHooks() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, link := range links {
		name := link.Attrs().Name
		if xdp := link.Attrs().Xdp; xdp != nil && xdp.Attached {
			return mismatchf("XDP program on link %s", name)
		}
		parents, err := filterParents(link)
		if err != nil {
			return err
		}
		for _, parent := range parents {
			filters, err := netlink.FilterList(link, parent)
			if err != nil {
				return fmt.Errorf("list tc filters on link %s: %w", name, err)
			}
			if len(filters) > 0 {
				return mismatchf("%d tc filters on link %s parent %#x", len(filters), name, parent)
			}
		}
	}
	return nil
}

// filterParents are the places a tc filter sits: the clsact hooks, the root,
// and each qdisc of the link.
func filterParents(link netlink.Link) ([]uint32, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("list qdiscs on link %s: %w", link.Attrs().Name, err)
	}
	parents := map[uint32]bool{
		netlink.HANDLE_MIN_INGRESS: true,
		netlink.HANDLE_MIN_EGRESS:  true,
		netlink.HANDLE_ROOT:        true,
	}
	for _, qdisc := range qdiscs {
		parents[qdisc.Attrs().Handle] = true
	}
	return slices.Collect(maps.Keys(parents)), nil
}
