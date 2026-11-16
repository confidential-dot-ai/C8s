//go:build linux

package ruleset

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The link types the tests describe, from include/uapi/linux/bpf.h: a tcx or
// netkit description carries an interface index of its own namespace, and a
// cgroup link carries no pod packets.
const (
	bpfLinkTypeCgroup = 3
	bpfLinkTypeTCX    = 11
	bpfLinkTypeNetkit = 13
)

// noBPFLinks replaces the enumeration for every namespace test: listing link
// IDs needs CAP_BPF in the initial user namespace, and what the host happens
// to have attached is not this package's subject.
func noBPFLinks(t *testing.T) {
	t.Helper()
	previous := enumerateBPFLinks
	enumerateBPFLinks = func() ([]bpfLink, error) { return nil, nil }
	t.Cleanup(func() { enumerateBPFLinks = previous })
}

// noHookPrograms replaces the hook query for the same reason: BPF_PROG_QUERY
// needs CAP_NET_ADMIN in the initial user namespace.
func noHookPrograms(t *testing.T) {
	t.Helper()
	previous := queryHookPrograms
	queryHookPrograms = noPrograms
	t.Cleanup(func() { queryHookPrograms = previous })
}

// requireBPFQuery skips when the kernel refuses a hook query, for the shells
// that hold no CAP_NET_ADMIN in the initial user namespace (an unshare-only
// one does not; sudo does).
func requireBPFQuery(t *testing.T) {
	t.Helper()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skipf("no loopback to probe with: %v", err)
	}
	if _, err := liveHookPrograms(uint32(lo.Attrs().Index), bpfTcxIngress); errors.Is(err, unix.EPERM) {
		t.Skip("needs CAP_NET_ADMIN in the initial user namespace: run under sudo")
	}
}

// The enforcer installs the ruleset into a pod's namespace and then verifies
// the live one against the same policy; the kernel must echo back exactly what
// was built, or every pod would be refused.
func TestVerifyAcceptsAFreshlyInstalledRulesetInTheNamespace(t *testing.T) {
	noBPFLinks(t)
	noHookPrograms(t)
	podNetNS(t, func(netnsPath string) error {
		if err := Install(netnsPath, testPolicy()); err != nil {
			return err
		}
		if err := Verify(netnsPath, testPolicy()); err != nil {
			t.Errorf("verify after install = %v", err)
		}
		return nil
	})
}

// Anything in the namespace that the policy did not put there is a refusal,
// and the refusal says what it was: the enforcer gates containers on this
// answer.
func TestVerifyRejectsTamperingInTheNamespace(t *testing.T) {
	tests := []struct {
		name   string
		wants  string
		tamper func(*nftables.Conn, *nftables.Table) error
	}{
		{"rule appended", "rules, expected", func(conn *nftables.Conn, table *nftables.Table) error {
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: &nftables.Chain{
					Name:  "filter-output",
					Table: table,
				},
				Exprs: withVerdict(matchTCPPort(9999), expr.VerdictAccept),
			})
			return conn.Flush()
		}},
		{"rule removed", "rules, expected", func(conn *nftables.Conn, table *nftables.Table) error {
			rules, err := conn.GetRules(table, &nftables.Chain{
				Name:  "filter-output",
				Table: table,
			})
			if err != nil {
				return err
			}
			if err := conn.DelRule(rules[0]); err != nil {
				return err
			}
			return conn.Flush()
		}},
		{"expression added to a rule", "expressions of chain", func(conn *nftables.Conn, table *nftables.Table) error {
			return widenRule(conn, table, &expr.Socket{
				Key:      expr.SocketKeyTransparent,
				Register: compareRegister,
			})
		}},
		{"set added", "sets, objects or flowtables", func(conn *nftables.Conn, table *nftables.Table) error {
			peers := &nftables.Set{
				Table:   table,
				Name:    "peers",
				KeyType: nftables.TypeIPAddr,
			}
			if err := conn.AddSet(peers, nil); err != nil {
				return err
			}
			return conn.Flush()
		}},
		{"chain added at an earlier hook in another table", "tables in the namespace", func(conn *nftables.Conn, _ *nftables.Table) error {
			other := conn.AddTable(&nftables.Table{
				Family: nftables.TableFamilyIPv4,
				Name:   "other",
			})
			conn.AddChain(&nftables.Chain{
				Name:     "raw-prerouting",
				Table:    other,
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookPrerouting,
				Priority: nftables.ChainPriorityRaw,
			})
			return conn.Flush()
		}},
		{"ruleset flushed", "tables in the namespace", func(conn *nftables.Conn, _ *nftables.Table) error {
			conn.FlushRuleset()
			return conn.Flush()
		}},
		{"tc filter on the clsact hook", "tc filters on link", func(_ *nftables.Conn, _ *nftables.Table) error {
			return attachClsactFilter()
		}},
		{"tc filter on a qdisc of the link", "tc filters on link", func(_ *nftables.Conn, _ *nftables.Table) error {
			return attachQdiscFilter()
		}},
		{"table made dormant", "pod table flags", func(_ *nftables.Conn, _ *nftables.Table) error {
			return setTableDormant()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			noBPFLinks(t)
			noHookPrograms(t)
			podNetNS(t, func(netnsPath string) error {
				if err := Install(netnsPath, testPolicy()); err != nil {
					return err
				}
				conn, err := nftables.New()
				if err != nil {
					return err
				}
				table := &nftables.Table{
					Family: nftables.TableFamilyINet,
					Name:   tableName,
				}
				if err := test.tamper(conn, table); err != nil {
					return fmt.Errorf("tamper: %w", err)
				}
				requireMismatch(t, Verify(netnsPath, testPolicy()), test.wants)
				return nil
			})
		})
	}
}

// A live ruleset built from another policy is refused, however small the
// difference: the enforcer verifies against the policy it installed.
func TestVerifyRejectsAnotherPolicysRulesetInTheNamespace(t *testing.T) {
	tests := []struct {
		name      string
		installed func(*Policy)
	}{
		{"changed capture port", func(p *Policy) { p.Capture.Outbound = 15002 }},
		{"changed resolver address", func(p *Policy) { p.Resolver = netip.MustParseAddr("10.53.0.11") }},
		{"changed role destination", func(p *Policy) { p.Roles[0].Destinations[0].Port = 9443 }},
		{"added role destination", func(p *Policy) {
			added := Destination{
				Addr: netip.MustParseAddr("10.43.0.3"),
				Port: 8443,
			}
			p.Roles[0].Destinations = append(p.Roles[0].Destinations, added)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			noBPFLinks(t)
			noHookPrograms(t)
			installed := testPolicy()
			test.installed(&installed)
			podNetNS(t, func(netnsPath string) error {
				if err := Install(netnsPath, installed); err != nil {
					return err
				}
				if err := Verify(netnsPath, testPolicy()); !errors.Is(err, ErrMismatch) {
					t.Errorf("verify = %v, want ErrMismatch", err)
				}
				return nil
			})
		})
	}
}

// A BPF attachment that reaches the pod's packets is a refusal, and one
// another namespace holds is none: a host-side link's description can match a
// pod interface's index only by accident, and the hook query, resolved in the
// pod's namespace, is what decides the pod's interfaces.
func TestVerifyRejectsPacketBPFLinksInTheNamespace(t *testing.T) {
	tests := []struct {
		name     string
		links    func(*testing.T, podNetwork) []bpfLink
		programs func(uint32, uint32) (int, error)
		refusal  string
	}{
		{"a tcx program on a pod interface", noLinksFor, programsOnHook(bpfTcxIngress), "tcx ingress BPF program on link"},
		{"a netkit program on a pod interface", noLinksFor, programsOnHook(bpfNetkitPrimary), "netkit primary BPF program on link"},
		{"a netns link on the pod namespace", func(_ *testing.T, pod podNetwork) []bpfLink {
			return []bpfLink{{linkType: bpfLinkTypeNetNS, target: uint32(pod.inode)}}
		}, noPrograms, "netns BPF link on this namespace"},
		{"a netfilter link anywhere", func(*testing.T, podNetwork) []bpfLink {
			return []bpfLink{{linkType: bpfLinkTypeNetfilter}}
		}, noPrograms, "netfilter BPF link on this node"},
		{"a host-side tcx link whose index matches a pod interface", func(t *testing.T, pod podNetwork) []bpfLink {
			return []bpfLink{{linkType: bpfLinkTypeTCX, target: anInterface(t, pod)}}
		}, noPrograms, ""},
		{"a host-side netkit link whose index matches a pod interface", func(t *testing.T, pod podNetwork) []bpfLink {
			return []bpfLink{{linkType: bpfLinkTypeNetkit, target: anInterface(t, pod)}}
		}, noPrograms, ""},
		{"a link type that carries no packets", func(t *testing.T, pod podNetwork) []bpfLink {
			return []bpfLink{{linkType: bpfLinkTypeCgroup, target: anInterface(t, pod)}}
		}, noPrograms, ""},
		{"a netkit hook of another device type", noLinksFor, hookError(bpfNetkitPrimary, unix.ENXIO), ""},
		{"a netkit hook on a kernel without netkit", noLinksFor, hookError(bpfNetkitPeer, unix.EINVAL), ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			podNetNS(t, func(netnsPath string) error {
				if err := Install(netnsPath, testPolicy()); err != nil {
					return err
				}
				inode, err := readNamespaceInode(netnsPath)
				if err != nil {
					return err
				}
				pod, err := readPodNetwork(inode)
				if err != nil {
					return err
				}
				bpfLinks(t, func() ([]bpfLink, error) { return test.links(t, pod), nil })
				hookPrograms(t, test.programs)
				requireRefusal(t, Verify(netnsPath, testPolicy()), test.refusal)
				return nil
			})
		})
	}
}

// A hook query the kernel refuses leaves the pod unverified, which is a
// failure, not a mismatch.
func TestVerifyFailsWhenHookQueryIsRefusedInTheNamespace(t *testing.T) {
	podNetNS(t, func(netnsPath string) error {
		if err := Install(netnsPath, testPolicy()); err != nil {
			return err
		}
		noBPFLinks(t)
		hookPrograms(t, hookError(bpfTcxIngress, unix.EPERM))
		err := Verify(netnsPath, testPolicy())
		if err == nil || errors.Is(err, ErrMismatch) {
			t.Errorf("verify = %v, want a failure that is no mismatch", err)
		}
		return nil
	})
}

// An enumeration the kernel refuses leaves the pod unverified, which is a
// failure, not a mismatch.
func TestVerifyFailsWhenBPFLinksCannotBeReadInTheNamespace(t *testing.T) {
	podNetNS(t, func(netnsPath string) error {
		if err := Install(netnsPath, testPolicy()); err != nil {
			return err
		}
		previous := enumerateBPFLinks
		enumerateBPFLinks = func() ([]bpfLink, error) { return nil, unix.EPERM }
		defer func() { enumerateBPFLinks = previous }()
		err := Verify(netnsPath, testPolicy())
		if err == nil || errors.Is(err, ErrMismatch) {
			t.Errorf("verify = %v, want a failure that is no mismatch", err)
		}
		return nil
	})
}

// The live hook query answers in the attached namespace: a fresh namespace
// has no programs on its loopback's tcx hooks, and the loopback's netkit
// hooks report only that they do not exist.
func TestHookQueryReportsNoProgramsInTheNamespace(t *testing.T) {
	requireBPFQuery(t)
	podNetNS(t, func(string) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		index := uint32(lo.Attrs().Index)
		for _, hook := range []uint32{bpfTcxIngress, bpfTcxEgress} {
			programs, err := liveHookPrograms(index, hook)
			if err != nil {
				return fmt.Errorf("query a tcx hook of loopback: %w", err)
			}
			if programs != 0 {
				return fmt.Errorf("a fresh namespace holds %d tcx programs on loopback", programs)
			}
		}
		for _, hook := range []uint32{bpfNetkitPrimary, bpfNetkitPeer} {
			if _, err := liveHookPrograms(index, hook); !errors.Is(err, unix.ENXIO) && !errors.Is(err, unix.EINVAL) {
				return fmt.Errorf("query a netkit hook of loopback = %v, want ENXIO or EINVAL", err)
			}
		}
		return nil
	})
}

// An attached program is counted: the query reads the count the kernel writes
// back, so a refusal cannot rest on a zero every attr buffer happens to hold.
func TestHookQueryCountsAnAttachedProgramInTheNamespace(t *testing.T) {
	probe, err := loadPassProgram()
	if errors.Is(err, unix.EPERM) {
		t.Skip("loading a BPF program needs CAP_BPF in the initial user namespace")
	}
	if err != nil {
		t.Fatalf("load a pass program: %v", err)
	}
	unix.Close(probe)
	podNetNS(t, func(netnsPath string) error {
		if err := Install(netnsPath, testPolicy()); err != nil {
			return err
		}
		noBPFLinks(t)
		iface, err := addDummy("hook0")
		if err != nil {
			return err
		}
		index := uint32(iface.Attrs().Index)
		program, err := loadPassProgram()
		if err != nil {
			return err
		}
		defer unix.Close(program)
		link, err := attachTCX(uint32(program), index, bpfTcxIngress)
		if err != nil {
			return fmt.Errorf("attach a tcx program: %w", err)
		}
		defer unix.Close(link)
		programs, err := liveHookPrograms(index, bpfTcxIngress)
		if err != nil {
			return err
		}
		if programs != 1 {
			return fmt.Errorf("query = %d programs, want the one attached", programs)
		}
		requireMismatch(t, Verify(netnsPath, testPolicy()), "tcx ingress BPF program on link hook0")
		return nil
	})
}

// An interface the query names can be gone: the kernel's ENODEV leaves the
// pod unverified rather than read as no programs.
func TestHookQueryFailsOnAVanishedInterfaceInTheNamespace(t *testing.T) {
	requireBPFQuery(t)
	podNetNS(t, func(string) error {
		iface, err := addDummy("gone0")
		if err != nil {
			return err
		}
		index := uint32(iface.Attrs().Index)
		if err := netlink.LinkDel(iface); err != nil {
			return fmt.Errorf("delete dummy: %w", err)
		}
		if _, err := liveHookPrograms(index, bpfTcxIngress); !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("query a deleted interface = %v, want ENODEV", err)
		}
		return nil
	})
}

// The bpf commands, program type, opcodes and tcx verdict the attach test
// needs, from bpf.h and bpf_common.h.
const (
	bpfProgLoad   = 5
	bpfLinkCreate = 28

	bpfProgTypeSchedCLS = 3
	tcxPass             = 0

	bpfMov64Imm = 0xb7
	bpfExit     = 0x95
)

// bpfInsn is one eBPF instruction as the verifier reads it.
type bpfInsn struct {
	code uint8
	regs uint8
	off  int16
	imm  int32
}

// bpfProgLoadAttr is the head of BPF_PROG_LOAD's attribute: the program type,
// and the instructions and license the verifier reads.
type bpfProgLoadAttr struct {
	progType uint32
	insnCnt  uint32
	insns    unsafe.Pointer
	license  unsafe.Pointer
}

// bpfLinkCreateAttr is the head of BPF_LINK_CREATE's attribute: the program,
// the interface and the hook it is linked to.
type bpfLinkCreateAttr struct {
	program    uint32
	ifindex    uint32
	attachType uint32
	flags      uint32
}

// loadPassProgram loads a two-instruction SCHED_CLS program that passes every
// packet: r0 is the return the kernel reads.
func loadPassProgram() (int, error) {
	program := []bpfInsn{
		{code: bpfMov64Imm, imm: tcxPass},
		{code: bpfExit},
	}
	license := []byte("GPL\x00")
	load := bpfProgLoadAttr{
		progType: bpfProgTypeSchedCLS,
		insnCnt:  uint32(len(program)),
		insns:    unsafe.Pointer(&program[0]),
		license:  unsafe.Pointer(&license[0]),
	}
	return bpfCall(bpfProgLoad, unsafe.Pointer(&load), unsafe.Sizeof(load))
}

// attachTCX links a loaded program to one tcx hook of the interface.
func attachTCX(program, ifindex, attachType uint32) (int, error) {
	link := bpfLinkCreateAttr{
		program:    program,
		ifindex:    ifindex,
		attachType: attachType,
	}
	return bpfCall(bpfLinkCreate, unsafe.Pointer(&link), unsafe.Sizeof(link))
}

// addDummy adds a dummy interface to the attached namespace.
func addDummy(name string) (*netlink.Dummy, error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	dummy := &netlink.Dummy{LinkAttrs: attrs}
	if err := netlink.LinkAdd(dummy); err != nil {
		return nil, fmt.Errorf("add dummy %s: %w", name, err)
	}
	return dummy, nil
}

// noLinksFor describes no links, whatever the pod holds.
func noLinksFor(*testing.T, podNetwork) []bpfLink { return nil }

func anInterface(t *testing.T, pod podNetwork) uint32 {
	t.Helper()
	for index := range pod.interfaces {
		return index
	}
	t.Fatal("the pod namespace has no interface to attach to")
	return 0
}

// requireMismatch requires a mismatch whose detail contains want.
func requireMismatch(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case !errors.Is(err, ErrMismatch):
		t.Errorf("verify = %v, want ErrMismatch", err)
	case !strings.Contains(err.Error(), want):
		t.Errorf("verify refused with %v, want %q in it", err, want)
	}
}

// widenRule adds one expression to a rule the ruleset expects, leaving a rule
// that decodes as the expected one through a library that skips expressions it
// does not know. Packet duplication cannot be tested this way: the kernel has
// no dup expression for an inet table, so a mirror needs a second table, which
// the table check already refuses.
func widenRule(conn *nftables.Conn, table *nftables.Table, added expr.Any) error {
	chain := &nftables.Chain{
		Name:  "filter-output",
		Table: table,
	}
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return err
	}
	widened := rules[len(rules)-1]
	widened.Exprs = append([]expr.Any{added}, widened.Exprs...)
	conn.ReplaceRule(widened)
	return conn.Flush()
}

// A tc filter can carry packets without passing the nftables hooks, whether it
// sits on the clsact hooks or on a qdisc of the link.
func attachClsactFilter() error {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	clsact := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.MakeHandle(0xffff, 0),
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(clsact); err != nil {
		return fmt.Errorf("add clsact qdisc: %w", err)
	}
	return addMatchAllFilter(link, netlink.HANDLE_MIN_EGRESS)
}

func attachQdiscFilter() error {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	handle := netlink.MakeHandle(1, 0)
	prio := netlink.NewPrio(netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_ROOT,
		Handle:    handle,
	})
	if err := netlink.QdiscAdd(prio); err != nil {
		return fmt.Errorf("add prio qdisc: %w", err)
	}
	return addMatchAllFilter(link, handle)
}

func addMatchAllFilter(link netlink.Link, parent uint32) error {
	filter := &netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{&netlink.GenericAction{ActionAttrs: netlink.ActionAttrs{Action: netlink.TC_ACT_OK}}},
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("add tc filter on parent %#x: %w", parent, err)
	}
	return nil
}

// setTableDormant unregisters the table's hooks while its chains and rules
// still list unchanged. github.com/google/nftables always sends flags 0, so
// the flag goes over raw netlink, in the batch nf_tables requires.
func setTableDormant() error {
	const dormant = 1
	conn, err := nfnl.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return fmt.Errorf("dial netfilter netlink: %w", err)
	}
	defer conn.Close()
	batch := netfilterHeader(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES)
	attributes, err := nfnl.MarshalAttributes([]nfnl.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: []byte(tableName + "\x00")},
		{Type: unix.NFTA_TABLE_FLAGS, Data: []byte{0, 0, 0, dormant}},
	})
	if err != nil {
		return err
	}
	newTable := nfnl.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWTABLE)
	request := []nfnl.Message{
		{
			Header: nfnl.Header{
				Type:  unix.NFNL_MSG_BATCH_BEGIN,
				Flags: nfnl.Request,
			},
			Data: batch,
		},
		{
			Header: nfnl.Header{
				Type:  newTable,
				Flags: nfnl.Request | nfnl.Acknowledge,
			},
			Data: append(netfilterHeader(unix.NFPROTO_INET, 0), attributes...),
		},
		{
			Header: nfnl.Header{
				Type:  unix.NFNL_MSG_BATCH_END,
				Flags: nfnl.Request,
			},
			Data: batch,
		},
	}
	if _, err := conn.SendMessages(request); err != nil {
		return fmt.Errorf("send dormant flag: %w", err)
	}
	if _, err := conn.Receive(); err != nil {
		return fmt.Errorf("set dormant flag: %w", err)
	}
	return nil
}

func netfilterHeader(family byte, resourceID uint16) []byte {
	header := make([]byte, nfgenmsgSize)
	header[0] = family
	header[1] = unix.NFNETLINK_V0
	header[2] = byte(resourceID >> 8)
	header[3] = byte(resourceID)
	return header
}
