//go:build linux

package ruleset

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// bpfLinkTypeCgroup is a link type that carries no pod packets, from
// include/uapi/linux/bpf.h.
const bpfLinkTypeCgroup = 3

// noBPFLinks replaces the enumeration for every namespace test: listing link
// IDs needs CAP_BPF in the initial user namespace, and what the host happens
// to have attached is not this package's subject.
func noBPFLinks(t *testing.T) {
	t.Helper()
	previous := enumerateBPFLinks
	enumerateBPFLinks = func() ([]bpfLink, error) { return nil, nil }
	t.Cleanup(func() { enumerateBPFLinks = previous })
}

// The enforcer installs the ruleset into a pod's namespace and then verifies
// the live one against the same policy; the kernel must echo back exactly what
// was built, or every pod would be refused.
func TestVerifyAcceptsAFreshlyInstalledRulesetInTheNamespace(t *testing.T) {
	noBPFLinks(t)
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
// and the reason says what it was: the enforcer gates containers on this
// answer.
func TestVerifyRejectsTamperingInTheNamespace(t *testing.T) {
	tests := []struct {
		name   string
		reason reason
		tamper func(*nftables.Conn, *nftables.Table) error
	}{
		{"rule appended", reasonRules, func(conn *nftables.Conn, table *nftables.Table) error {
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: &nftables.Chain{Name: "filter-output", Table: table},
				Exprs: withVerdict(matchTCPPort(9999), expr.VerdictAccept),
			})
			return conn.Flush()
		}},
		{"rule removed", reasonRules, func(conn *nftables.Conn, table *nftables.Table) error {
			rules, err := conn.GetRules(table, &nftables.Chain{Name: "filter-output", Table: table})
			if err != nil {
				return err
			}
			if err := conn.DelRule(rules[0]); err != nil {
				return err
			}
			return conn.Flush()
		}},
		{"expression added to a rule", reasonExpression, func(conn *nftables.Conn, table *nftables.Table) error {
			return widenRule(conn, table, &expr.Socket{Key: expr.SocketKeyTransparent, Register: compareRegister})
		}},
		{"set added", reasonNamedState, func(conn *nftables.Conn, table *nftables.Table) error {
			if err := conn.AddSet(&nftables.Set{Table: table, Name: "peers", KeyType: nftables.TypeIPAddr}, nil); err != nil {
				return err
			}
			return conn.Flush()
		}},
		{"chain added at an earlier hook in another table", reasonTables, func(conn *nftables.Conn, _ *nftables.Table) error {
			other := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "other"})
			conn.AddChain(&nftables.Chain{
				Name: "raw-prerouting", Table: other, Type: nftables.ChainTypeFilter,
				Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRaw,
			})
			return conn.Flush()
		}},
		{"ruleset flushed", reasonTables, func(conn *nftables.Conn, _ *nftables.Table) error {
			conn.FlushRuleset()
			return conn.Flush()
		}},
		{"tc filter on the clsact hook", reasonPacketHook, func(_ *nftables.Conn, _ *nftables.Table) error {
			return attachClsactFilter()
		}},
		{"tc filter on a qdisc of the link", reasonPacketHook, func(_ *nftables.Conn, _ *nftables.Table) error {
			return attachQdiscFilter()
		}},
		{"table made dormant", reasonTableFlags, func(_ *nftables.Conn, _ *nftables.Table) error {
			return setTableDormant()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			noBPFLinks(t)
			podNetNS(t, func(netnsPath string) error {
				if err := Install(netnsPath, testPolicy()); err != nil {
					return err
				}
				conn, err := nftables.New()
				if err != nil {
					return err
				}
				table := &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
				if err := test.tamper(conn, table); err != nil {
					return fmt.Errorf("tamper: %w", err)
				}
				requireMismatch(t, Verify(netnsPath, testPolicy()), test.reason)
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
		{"changed resolver address", func(p *Policy) { p.Resolvers[0] = netip.MustParseAddr("10.53.0.11") }},
		{"changed role destination", func(p *Policy) { p.Roles[0].Destinations[0].Port = 9443 }},
		{"added role destination", func(p *Policy) {
			p.Roles[0].Destinations = append(p.Roles[0].Destinations, Destination{netip.MustParseAddr("10.43.0.3"), 8443})
		}},
		{"reordered resolvers", func(p *Policy) { p.Resolvers[0], p.Resolvers[1] = p.Resolvers[1], p.Resolvers[0] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			noBPFLinks(t)
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

// A BPF link attached where it sees the pod's packets is a refusal.
func TestVerifyRejectsPacketBPFLinksInTheNamespace(t *testing.T) {
	tests := []struct {
		name     string
		link     func(*testing.T, podNetwork) bpfLink
		mismatch bool
	}{
		{"tcx on a pod interface", func(t *testing.T, pod podNetwork) bpfLink {
			return bpfLink{linkType: bpfLinkTypeTCX, target: anInterface(t, pod)}
		}, true},
		{"netkit on a pod interface", func(t *testing.T, pod podNetwork) bpfLink {
			return bpfLink{linkType: bpfLinkTypeNetkit, target: anInterface(t, pod)}
		}, true},
		{"netns on the pod namespace", func(_ *testing.T, pod podNetwork) bpfLink {
			return bpfLink{linkType: bpfLinkTypeNetNS, target: uint32(pod.inode)}
		}, true},
		{"netfilter anywhere", func(*testing.T, podNetwork) bpfLink {
			return bpfLink{linkType: bpfLinkTypeNetfilter}
		}, true},
		{"tcx on another namespace's interface", func(t *testing.T, pod podNetwork) bpfLink {
			return bpfLink{linkType: bpfLinkTypeTCX, target: noInterface(pod)}
		}, false},
		{"a link type that carries no packets", func(t *testing.T, pod podNetwork) bpfLink {
			return bpfLink{linkType: bpfLinkTypeCgroup, target: anInterface(t, pod)}
		}, false},
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
				links := []bpfLink{test.link(t, pod)}
				previous := enumerateBPFLinks
				enumerateBPFLinks = func() ([]bpfLink, error) { return links, nil }
				defer func() { enumerateBPFLinks = previous }()
				err = Verify(netnsPath, testPolicy())
				if !test.mismatch {
					if err != nil {
						t.Errorf("verify = %v, want no error", err)
					}
					return nil
				}
				requireMismatch(t, err, reasonBPFLink)
				return nil
			})
		})
	}
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

func anInterface(t *testing.T, pod podNetwork) uint32 {
	t.Helper()
	for index := range pod.interfaces {
		return index
	}
	t.Fatal("the pod namespace has no interface to attach to")
	return 0
}

func noInterface(pod podNetwork) uint32 {
	index := uint32(1)
	for {
		if _, used := pod.interfaces[index]; !used {
			return index
		}
		index++
	}
}

func requireMismatch(t *testing.T, err error, want reason) {
	t.Helper()
	var refused mismatch
	switch {
	case !errors.Is(err, ErrMismatch):
		t.Errorf("verify = %v, want ErrMismatch", err)
	case !errors.As(err, &refused):
		t.Errorf("verify = %v, want a mismatch carrying a reason", err)
	case refused.reason != want:
		t.Errorf("verify refused for %q, want %q", refused.reason, want)
	}
}

// widenRule adds one expression to a rule the ruleset expects, leaving a rule
// that decodes as the expected one through a library that skips expressions it
// does not know. Packet duplication cannot be tested this way: the kernel has
// no dup expression for an inet table, so a mirror needs a second table, which
// the table check already refuses.
func widenRule(conn *nftables.Conn, table *nftables.Table, added expr.Any) error {
	chain := &nftables.Chain{Name: "filter-output", Table: table}
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
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_CLSACT, Handle: netlink.MakeHandle(0xffff, 0)},
		QdiscType:  "clsact",
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
	prio := netlink.NewPrio(netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_ROOT, Handle: handle})
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
		{Header: nfnl.Header{Type: unix.NFNL_MSG_BATCH_BEGIN, Flags: nfnl.Request}, Data: batch},
		{
			Header: nfnl.Header{Type: newTable, Flags: nfnl.Request | nfnl.Acknowledge},
			Data:   append(netfilterHeader(unix.NFPROTO_INET, 0), attributes...),
		},
		{Header: nfnl.Header{Type: unix.NFNL_MSG_BATCH_END, Flags: nfnl.Request}, Data: batch},
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
