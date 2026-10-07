//go:build linux

package ruleset

import (
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A ruleset that cannot be built is never verified against.
func TestVerifyRefusesInvalidPolicy(t *testing.T) {
	if err := Verify("/proc/self/ns/net", Policy{}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("error = %v, want ErrPolicy", err)
	}
}

// The kernel omits the nested flag its own encoder sets, and that is the only
// difference the comparison may ignore.
func TestAttributeComparisonIgnoresOnlyTheNestedFlag(t *testing.T) {
	value := nfnl.Attribute{Type: nftaPayload, Data: []byte{1, 2, 3, 4}}
	expected := marshal(t, nfnl.Attribute{Type: unix.NFTA_LIST_ELEM | unix.NLA_F_NESTED, Data: marshal(t, value)})
	live := marshal(t, nfnl.Attribute{Type: unix.NFTA_LIST_ELEM, Data: marshal(t, value)})
	if err := compareAttributes(expected, live); err != nil {
		t.Fatalf("comparison of the same tree = %v", err)
	}
}

// Whatever the kernel reports instead of the expected tree, it is a
// difference: a value where a tree belongs, a tree where a value belongs, an
// attribute more, one fewer, or one changed.
func TestAttributeComparisonRejectsEveryDifference(t *testing.T) {
	const (
		name  = unix.NFTA_EXPR_NAME
		value = nftaPayload
	)
	expected := marshal(t,
		nfnl.Attribute{Type: name, Data: []byte("meta")},
		nfnl.Attribute{Type: value, Data: []byte{0, 0, 0, 10}},
	)
	nested := marshal(t,
		nfnl.Attribute{Type: name, Data: []byte("meta")},
		nfnl.Attribute{Type: value | unix.NLA_F_NESTED, Data: marshal(t, nfnl.Attribute{Type: name, Data: []byte{1}})},
	)
	tests := []struct {
		name string
		live []byte
	}{
		{"attribute added", marshal(t,
			nfnl.Attribute{Type: name, Data: []byte("meta")},
			nfnl.Attribute{Type: value, Data: []byte{0, 0, 0, 10}},
			nfnl.Attribute{Type: value + 1, Data: []byte{1}},
		)},
		{"attribute dropped", marshal(t, nfnl.Attribute{Type: name, Data: []byte("meta")})},
		{"value changed", marshal(t,
			nfnl.Attribute{Type: name, Data: []byte("meta")},
			nfnl.Attribute{Type: value, Data: []byte{0, 0, 0, 11}},
		)},
		{"type changed", marshal(t,
			nfnl.Attribute{Type: name, Data: []byte("meta")},
			nfnl.Attribute{Type: value + 2, Data: []byte{0, 0, 0, 10}},
		)},
		{"tree where a value belongs", nested},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := compareAttributes(expected, test.live); err == nil {
				t.Fatal("comparison accepted a difference")
			}
		})
	}
}

// A leaf the kernel reports where the expected tree has sub-attributes cannot
// read as that tree.
func TestAttributeComparisonRejectsALeafWhereATreeIsExpected(t *testing.T) {
	expected := marshal(t, nfnl.Attribute{
		Type: unix.NFTA_LIST_ELEM | unix.NLA_F_NESTED,
		Data: marshal(t, nfnl.Attribute{Type: unix.NFTA_EXPR_NAME, Data: []byte("meta")}),
	})
	live := marshal(t, nfnl.Attribute{Type: unix.NFTA_LIST_ELEM, Data: []byte{9, 9, 9, 9}})
	if err := compareAttributes(expected, live); err == nil {
		t.Fatal("comparison accepted a value where a tree is expected")
	}
}

// The description of a link is read where its fields are, and a short one is
// refused.
func TestBPFLinkInfoReadsTheTypeAndItsTarget(t *testing.T) {
	info := make([]byte, bpfLinkInfoSize)
	putNative(info[0:], bpfLinkTypeTCX)
	putNative(info[unsafe.Offsetof(bpfLinkInfo{}.Target):], 7)
	link, err := readBPFLinkInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	if link.linkType != bpfLinkTypeTCX || link.target != 7 {
		t.Fatalf("link = %+v, want type %d target 7", link, bpfLinkTypeTCX)
	}
	if _, err := readBPFLinkInfo(info[:bpfLinkInfoSize-1]); err == nil {
		t.Fatal("a short link description was accepted")
	}
}

// A namespace handle that cannot be read leaves the pod unverified, which is
// a failure, not a mismatch.
func TestVerifyFailsOnAnUnreadableNamespace(t *testing.T) {
	err := Verify(filepath.Join(t.TempDir(), "absent"), testPolicy())
	if err == nil || errors.Is(err, ErrMismatch) {
		t.Fatalf("verify = %v, want a failure that is no mismatch", err)
	}
}

// The namespace is identified by the handle the caller named, which is what a
// link description is compared against.
func TestNamespaceInodeDescribesTheNamedHandle(t *testing.T) {
	inode, err := readNamespaceInode("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	var described unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &described); err != nil {
		t.Fatal(err)
	}
	if inode != described.Ino {
		t.Fatalf("inode = %d, want %d", inode, described.Ino)
	}
	if _, err := readNamespaceInode(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("an absent namespace handle was accepted")
	}
}

// The namespace holds the pod table in the inet family with no flag set:
// another table, another family, or a dormant table is a refusal.
func TestTableCheckAcceptsOnlyThePodTable(t *testing.T) {
	tests := []struct {
		name   string
		tables [][]byte
		wants  string
	}{
		{"the pod table alone", [][]byte{tableReply(t, unix.NFPROTO_INET, tableName, 0)}, ""},
		{"no table", nil, "0 tables in the namespace"},
		{"a second table", [][]byte{
			tableReply(t, unix.NFPROTO_INET, tableName, 0),
			tableReply(t, unix.NFPROTO_IPV4, "other", 0),
		}, "2 tables in the namespace"},
		{"another name", [][]byte{tableReply(t, unix.NFPROTO_INET, "other", 0)}, `table "other"`},
		{"another family", [][]byte{tableReply(t, unix.NFPROTO_IPV4, tableName, 0)}, "in family"},
		{"a dormant table", [][]byte{tableReply(t, unix.NFPROTO_INET, tableName, 1)}, "pod table flags"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftDumps(t, map[uint16][][]byte{unix.NFT_MSG_GETTABLE: test.tables})
			requireRefusal(t, requireOnlyPodTable(conn), test.wants)
		})
	}
}

// The ruleset names no set, stateful object or flowtable, so one in the
// namespace is a refusal whatever it holds.
func TestNamedStateCheckRejectsEverySet(t *testing.T) {
	tests := []struct {
		name  string
		dump  uint16
		wants string
	}{
		{"no named state", 0, ""},
		{"a set", unix.NFT_MSG_GETSET, "sets, objects or flowtables"},
		{"a stateful object", unix.NFT_MSG_GETOBJ, "sets, objects or flowtables"},
		{"a flowtable", unix.NFT_MSG_GETFLOWTABLE, "sets, objects or flowtables"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dumps := map[uint16][][]byte{}
			if test.dump != 0 {
				dumps[test.dump] = [][]byte{nftReply(t, unix.NFPROTO_INET)}
			}
			requireRefusal(t, requireNoNamedState(nftDumps(t, dumps)), test.wants)
		})
	}
}

// The namespace holds the expected base chains and nothing else, each
// registered where the ruleset expects it.
func TestChainCheckRequiresTheExpectedChainsWhereTheyRegister(t *testing.T) {
	expected := build(testPolicy())
	rehooked := func(change func(*chain)) [][]byte {
		changed := slices.Clone(expected)
		change(&changed[0])
		return chainReplies(t, changed)
	}
	tests := []struct {
		name   string
		chains [][]byte
		wants  string
	}{
		{"the expected chains", chainReplies(t, expected), ""},
		{"a chain is absent", chainReplies(t, expected[1:]), "is absent"},
		{"a chain twice", append(chainReplies(t, expected), chainReplies(t, expected[:1])...), "twice"},
		{"a chain that is not expected", append(chainReplies(t, expected), chainReply(t, chain{name: "extra"})), "chain extra is not expected"},
		{"another hook", rehooked(func(c *chain) { c.hook++ }), "at hook"},
		{"another priority", rehooked(func(c *chain) { c.priority++ }), "at hook"},
		{"another policy", rehooked(func(c *chain) { c.policy = nftables.ChainPolicyDrop }), "at hook"},
		{"another type", rehooked(func(c *chain) { c.kind = nftables.ChainTypeRoute }), "at hook"},
		{"a chain that is not hooked", [][]byte{nftReply(t, unix.NFPROTO_INET,
			nfnl.Attribute{Type: unix.NFTA_CHAIN_NAME, Data: nftName(expected[0].name)},
		)}, "is not hooked"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftDumps(t, map[uint16][][]byte{unix.NFT_MSG_GETCHAIN: test.chains})
			requireRefusal(t, requireChains(conn, expected), test.wants)
		})
	}
}

// Every chain holds the expected rules, in the order the kernel evaluates
// them, with the expected expressions and no others.
func TestRuleCheckRequiresTheExpectedRulesInOrder(t *testing.T) {
	expected := build(testPolicy())
	installed := ruleReplies(t, tableName, expected)
	widened := slices.Clone(installed)
	widened[0] = ruleReply(t, tableName, expected[0].name, expressions(t, rule{
		name:  expected[0].rules[0].name,
		exprs: append([]expr.Any{&expr.Counter{}}, expected[0].rules[0].exprs...),
	}))
	tests := []struct {
		name  string
		rules [][]byte
		wants string
	}{
		{"the installed rules", installed, ""},
		{"a rule appended", append(slices.Clone(installed), installed[0]), "rules, expected"},
		{"a rule removed", installed[1:], "rules, expected"},
		{"a rule in another table", ruleReplies(t, "other", expected), `rule in table "other"`},
		{"rules in a chain that is not expected", append(slices.Clone(installed), ruleReply(t, tableName, "extra", nil)), "rules in chain extra"},
		{"an expression added to a rule", widened, "expressions of chain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftDumps(t, map[uint16][][]byte{unix.NFT_MSG_GETRULE: test.rules})
			requireRefusal(t, requireRules(conn, expected), test.wants)
		})
	}
}

// A BPF link is refused for what its description names: an interface of the
// pod, the pod's namespace, or the node for a link type that names neither.
func TestPacketBPFLinkCheckRefusesWhatReachesThePod(t *testing.T) {
	pod := podNetwork{
		inode:      4026532748,
		interfaces: map[uint32]string{1: "lo", 2: "eth0"},
	}
	tests := []struct {
		name    string
		link    bpfLink
		refused bool
	}{
		{"tcx on a pod interface", bpfLink{bpfLinkTypeTCX, 2}, true},
		{"netkit on a pod interface", bpfLink{bpfLinkTypeNetkit, 2}, true},
		{"netns on the pod namespace", bpfLink{bpfLinkTypeNetNS, uint32(pod.inode)}, true},
		{"netfilter anywhere on the node", bpfLink{bpfLinkTypeNetfilter, 0}, true},
		{"tcx on another namespace's interface", bpfLink{bpfLinkTypeTCX, 3}, false},
		{"netns on another namespace", bpfLink{bpfLinkTypeNetNS, 7}, false},
		{"a link type that carries no packets", bpfLink{bpfLinkTypeCgroup, 2}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bpfLinks(t, func() ([]bpfLink, error) { return []bpfLink{test.link}, nil })
			refusal := ""
			if test.refused {
				refusal = "BPF link"
			}
			requireRefusal(t, requireNoPacketBPFLinks(pod), refusal)
		})
	}
}

// A namespace a link description cannot name and an enumeration the kernel
// refuses both leave the pod unverified, which is no mismatch.
func TestPacketBPFLinkCheckFailsWhenLinksCannotBeDecided(t *testing.T) {
	tests := []struct {
		name  string
		pod   podNetwork
		links func() ([]bpfLink, error)
	}{
		{"an inode wider than a link description", podNetwork{inode: math.MaxUint32 + 1}, func() ([]bpfLink, error) { return nil, nil }},
		{"an enumeration the kernel refuses", podNetwork{}, func() ([]bpfLink, error) { return nil, unix.EPERM }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bpfLinks(t, test.links)
			err := requireNoPacketBPFLinks(test.pod)
			if err == nil || errors.Is(err, ErrMismatch) {
				t.Fatalf("BPF link check = %v, want a failure that is no mismatch", err)
			}
		})
	}
}

// The interfaces a link description could name are read from the attached
// namespace, under the inode the caller read from the handle.
func TestPodNetworkReadsTheAttachedInterfaces(t *testing.T) {
	pod, err := readPodNetwork(42)
	if err != nil {
		t.Fatal(err)
	}
	if pod.inode != 42 {
		t.Fatalf("inode = %d, want 42", pod.inode)
	}
	if !slices.Contains(slices.Collect(maps.Values(pod.interfaces)), "lo") {
		t.Fatalf("interfaces = %v, want the loopback among them", pod.interfaces)
	}
}

// A tc filter is looked for on the clsact hooks, the root and every qdisc of
// the link.
func TestFilterParentsCoverTheClsactHooksAndTheRoot(t *testing.T) {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	parents, err := filterParents(link)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS, netlink.HANDLE_ROOT} {
		if !slices.Contains(parents, want) {
			t.Errorf("parents = %#x, want %#x among them", parents, want)
		}
	}
}

// A refusal is a mismatch and names what differed, so a log says why a pod
// was refused.
func TestARefusalNamesWhatDiffered(t *testing.T) {
	err := mismatchf("%d tables", 2)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("error = %v, want ErrMismatch", err)
	}
	if !strings.Contains(err.Error(), "2 tables") {
		t.Errorf("error = %q, want the detail in it", err)
	}
}

// A dump the kernel refuses and a reply that does not read as netfilter
// attributes leave the pod unverified, which is a failure, not a mismatch.
func TestRulesetChecksFailOnAnUnreadableDump(t *testing.T) {
	expected := build(testPolicy())
	chains := func(conn *nfnl.Conn) error { return requireChains(conn, expected) }
	rules := func(conn *nfnl.Conn) error { return requireRules(conn, expected) }
	truncated := make([]byte, nfgenmsgSize-1)
	unattributed := append(netfilterHeader(unix.NFPROTO_INET, 0), 1, 2)
	tests := []struct {
		name  string
		dump  uint16
		reply []byte // nil refuses the dump itself
		check func(*nfnl.Conn) error
	}{
		{"the table dump is refused", unix.NFT_MSG_GETTABLE, nil, requireOnlyPodTable},
		{"a table reply holds no attributes", unix.NFT_MSG_GETTABLE, unattributed, requireOnlyPodTable},
		{"a table reply is shorter than the netfilter header", unix.NFT_MSG_GETTABLE, truncated, requireOnlyPodTable},
		{"a table flag is narrower than it reads", unix.NFT_MSG_GETTABLE, nftReply(t, unix.NFPROTO_INET,
			nfnl.Attribute{Type: unix.NFTA_TABLE_FLAGS, Data: []byte{0, 0}},
		), requireOnlyPodTable},
		{"the set dump is refused", unix.NFT_MSG_GETSET, nil, requireNoNamedState},
		{"the chain dump is refused", unix.NFT_MSG_GETCHAIN, nil, chains},
		{"a chain reply is shorter than the netfilter header", unix.NFT_MSG_GETCHAIN, truncated, chains},
		{"a chain policy is narrower than it reads", unix.NFT_MSG_GETCHAIN, nftReply(t, unix.NFPROTO_INET,
			nfnl.Attribute{Type: unix.NFTA_CHAIN_POLICY, Data: []byte{0, 0}},
		), chains},
		{"the rule dump is refused", unix.NFT_MSG_GETRULE, nil, rules},
		{"a rule reply is shorter than the netfilter header", unix.NFT_MSG_GETRULE, truncated, rules},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftError(t, unix.EPERM)
			if test.reply != nil {
				conn = nftDumps(t, map[uint16][][]byte{test.dump: {test.reply}})
			}
			err := test.check(conn)
			if err == nil || errors.Is(err, ErrMismatch) {
				t.Fatalf("check = %v, want a failure that is no mismatch", err)
			}
		})
	}
}

// An expression the comparison cannot encode leaves the pod unverified: a rule
// that cannot be stated is never one the kernel agrees with.
func TestRuleCheckFailsOnAnExpressionItCannotEncode(t *testing.T) {
	unencodable := chain{
		name: "filter-output",
		rules: []rule{
			{"too-wide-mask", []expr.Any{&expr.Bitwise{Mask: make([]byte, math.MaxUint16)}}},
		},
	}
	if _, err := marshalExpressions(unencodable.rules[0]); err == nil {
		t.Fatal("an expression wider than an attribute was encoded")
	}
	conn := nftDumps(t, map[uint16][][]byte{
		unix.NFT_MSG_GETRULE: {ruleReply(t, tableName, unencodable.name, nil)},
	})
	err := requireRules(conn, []chain{unencodable})
	if err == nil || errors.Is(err, ErrMismatch) {
		t.Fatalf("rule check = %v, want a failure that is no mismatch", err)
	}
}

// Attributes that cannot be decoded are no match: a comparison that cannot
// read both sides must not accept the rule.
func TestAttributeComparisonFailsOnAttributesItCannotDecode(t *testing.T) {
	unattributed := []byte{1, 2}
	if err := compareAttributes(unattributed, nil); err == nil {
		t.Error("a comparison accepted expected attributes it cannot decode")
	}
	if err := compareAttributes(nil, unattributed); err == nil {
		t.Error("a comparison accepted live attributes it cannot decode")
	}
}

// The namespace the tests run in is not a protected pod namespace, whether it
// can be attached to or not.
func TestVerifyRefusesTheNamespaceItRunsIn(t *testing.T) {
	if err := Verify("/proc/self/ns/net", testPolicy()); err == nil {
		t.Fatal("verify accepted the namespace it runs in")
	}
}

// The hook check reads every link of the attached namespace: a packet hook is
// the only refusal it answers with, and listing the links, their qdiscs and
// their filters must not fail.
func TestPacketHookCheckRefusesOnlyForAHookOnALink(t *testing.T) {
	if err := requireNoPacketHooks(); err != nil {
		requireMismatch(t, err, "on link")
	}
}

// Walking link IDs needs CAP_BPF in the initial user namespace: without it the
// walk reports the kernel's refusal rather than an empty set, which would
// admit a pod whose links were never read.
func TestBPFLinkWalkFailsWithoutTheCapability(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("holds CAP_BPF, so the kernel answers the walk")
	}
	if links, err := liveBPFLinks(); err == nil {
		t.Fatalf("walk = %v, want the kernel's refusal", links)
	}
}

// nftaPayload is an attribute type these cases use as an opaque leaf.
const nftaPayload = 2

func marshal(t *testing.T, attributes ...nfnl.Attribute) []byte {
	t.Helper()
	encoded, err := nfnl.MarshalAttributes(attributes)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func putNative(target []byte, value uint32) {
	binary.NativeEndian.PutUint32(target, value)
}

// requireRefusal requires a refusal naming want, or no error when it is
// empty.
func requireRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("check = %v, want no error", err)
		}
		return
	}
	requireMismatch(t, err, want)
}

// bpfLinks drives link decisions from the test instead of the kernel.
func bpfLinks(t *testing.T, enumerate func() ([]bpfLink, error)) {
	t.Helper()
	previous := enumerateBPFLinks
	enumerateBPFLinks = enumerate
	t.Cleanup(func() { enumerateBPFLinks = previous })
}

// nftDumps answers each nftables dump with the replies given for its message
// kind, as the multi-part reply the kernel sends.
func nftDumps(t *testing.T, dumps map[uint16][][]byte) *nfnl.Conn {
	t.Helper()
	return nftConn(t, func(request []nfnl.Message) ([]nfnl.Message, error) {
		if len(request) != 1 {
			return nil, io.EOF
		}
		header := request[0].Header
		var replies []nfnl.Message
		for _, data := range dumps[uint16(header.Type)&0xff] {
			replies = append(replies, nfnl.Message{
				Header: nfnl.Header{
					Type:     header.Type,
					Flags:    nfnl.Multi,
					Sequence: header.Sequence,
				},
				Data: data,
			})
		}
		return append(replies, nfnl.Message{
			Header: nfnl.Header{
				Type:     nfnl.Done,
				Flags:    nfnl.Multi,
				Sequence: header.Sequence,
			},
		}), nil
	})
}

func nftError(t *testing.T, errno unix.Errno) *nfnl.Conn {
	t.Helper()
	return nftConn(t, func(request []nfnl.Message) ([]nfnl.Message, error) {
		return nltest.Error(int(errno), request)
	})
}

func nftConn(t *testing.T, answer nltest.Func) *nfnl.Conn {
	t.Helper()
	conn := nltest.Dial(answer)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// nftReply encodes one dump reply: the netfilter header, then attributes.
func nftReply(t *testing.T, family byte, attributes ...nfnl.Attribute) []byte {
	t.Helper()
	return append(netfilterHeader(family, 0), marshal(t, attributes...)...)
}

func tableReply(t *testing.T, family byte, name string, flags uint32) []byte {
	t.Helper()
	return nftReply(t, family,
		nfnl.Attribute{Type: unix.NFTA_TABLE_NAME, Data: nftName(name)},
		nfnl.Attribute{Type: unix.NFTA_TABLE_FLAGS, Data: binaryutil.BigEndian.PutUint32(flags)},
	)
}

func chainReplies(t *testing.T, chains []chain) [][]byte {
	t.Helper()
	replies := make([][]byte, 0, len(chains))
	for _, c := range chains {
		replies = append(replies, chainReply(t, c))
	}
	return replies
}

func chainReply(t *testing.T, c chain) []byte {
	t.Helper()
	hook := marshal(t,
		nfnl.Attribute{Type: unix.NFTA_HOOK_HOOKNUM, Data: binaryutil.BigEndian.PutUint32(uint32(c.hook))},
		nfnl.Attribute{Type: unix.NFTA_HOOK_PRIORITY, Data: binaryutil.BigEndian.PutUint32(uint32(c.priority))},
	)
	return nftReply(t, unix.NFPROTO_INET,
		nfnl.Attribute{Type: unix.NFTA_CHAIN_NAME, Data: nftName(c.name)},
		nfnl.Attribute{Type: unix.NFTA_CHAIN_TYPE, Data: nftName(string(c.kind))},
		nfnl.Attribute{Type: unix.NFTA_CHAIN_POLICY, Data: binaryutil.BigEndian.PutUint32(uint32(c.policy))},
		nfnl.Attribute{Type: unix.NFTA_CHAIN_HOOK | unix.NLA_F_NESTED, Data: hook},
	)
}

func ruleReplies(t *testing.T, table string, chains []chain) [][]byte {
	t.Helper()
	var replies [][]byte
	for _, c := range chains {
		for _, r := range c.rules {
			replies = append(replies, ruleReply(t, table, c.name, expressions(t, r)))
		}
	}
	return replies
}

func ruleReply(t *testing.T, table, chainName string, exprs []byte) []byte {
	t.Helper()
	return nftReply(t, unix.NFPROTO_INET,
		nfnl.Attribute{Type: unix.NFTA_RULE_TABLE, Data: nftName(table)},
		nfnl.Attribute{Type: unix.NFTA_RULE_CHAIN, Data: nftName(chainName)},
		nfnl.Attribute{Type: unix.NFTA_RULE_EXPRESSIONS, Data: exprs},
	)
}

func expressions(t *testing.T, r rule) []byte {
	t.Helper()
	encoded, err := marshalExpressions(r)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func nftName(name string) []byte {
	return []byte(name + "\x00")
}
