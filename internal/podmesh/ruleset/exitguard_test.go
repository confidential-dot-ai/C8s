//go:build linux

package ruleset

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	guardSources = []netip.Addr{netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("fd00:42::7")}
	guardExits   = []Exit{
		{netip.MustParsePrefix("203.0.113.0/24"), 443},
		{netip.MustParsePrefix("2001:db8::/32"), 8443},
	}
)

// Each source is paired only with the exits of its own family.
func TestBuildGuardPairsSourcesWithExitsOfTheirFamily(t *testing.T) {
	got := buildGuard(4026532001, guardSources, guardExits)
	if got.name != "pod-netns-4026532001" {
		t.Errorf("buildGuard name = %q, want pod-netns-4026532001", got.name)
	}
	var names []string
	for _, r := range got.rules {
		names = append(names, r.name)
	}
	want := []string{
		"translated-exit-203.0.113.0/24-443-from-10.42.0.7",
		"translated-exit-2001:db8::/32-8443-from-fd00:42::7",
	}
	if !slices.Equal(names, want) {
		t.Errorf("buildGuard rules = %q, want %q", names, want)
	}
	for _, r := range got.rules {
		if verdict, ok := r.exprs[len(r.exprs)-1].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictDrop {
			t.Errorf("rule %s ends with %#v, want a drop", r.name, r.exprs[len(r.exprs)-1])
		}
	}
}

func TestGuardForRefusesWhatItCannotGuard(t *testing.T) {
	tests := []struct {
		name  string
		exits []Exit
		wants string
	}{
		{"no exits", nil, "no exits to guard"},
		{"an exit with host bits", []Exit{{netip.MustParsePrefix("203.0.113.1/24"), 443}}, "host bits"},
		{"an exit with no port", []Exit{{netip.MustParsePrefix("203.0.113.0/24"), 0}}, "no port"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := guardFor("/nonexistent/netns", test.exits)
			if !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("guardFor = %v, want a policy error naming %q", err, test.wants)
			}
		})
	}
	if _, err := guardFor("/nonexistent/netns", guardExits); err == nil {
		t.Fatal("guardFor on a missing namespace = nil, want an error")
	}
}

// Every entry point fails, without touching any namespace, on one it cannot
// open.
func TestExitGuardFailsOnAnUnreadableNamespace(t *testing.T) {
	const missing = "/nonexistent/netns"
	checks := map[string]error{
		"GuardExits":       GuardExits(missing, missing, guardExits),
		"VerifyExitGuard":  VerifyExitGuard(missing, missing, guardExits),
		"ReleaseExitGuard": ReleaseExitGuard(missing, 4026532001),
	}
	_, checks["ExitGuards"] = ExitGuards(missing)
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s(%s) = nil, want an error", name, missing)
		}
	}
}

func TestGuardTableCheckRequiresAnActiveInetTable(t *testing.T) {
	tests := []struct {
		name   string
		tables [][]byte
		wants  string
	}{
		{"the guard table among the node's", [][]byte{
			tableReply(t, unix.NFPROTO_IPV4, "kube-proxy", 0),
			tableReply(t, unix.NFPROTO_INET, guardTableName, 0),
		}, ""},
		{"no table", nil, "is absent"},
		{"the name in another family", [][]byte{tableReply(t, unix.NFPROTO_IPV4, guardTableName, 0)}, "is absent"},
		{"a dormant table", [][]byte{tableReply(t, unix.NFPROTO_INET, guardTableName, 1)}, "table flags"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftDumps(t, map[uint16][][]byte{unix.NFT_MSG_GETTABLE: test.tables})
			requireRefusal(t, requireGuardTable(conn), test.wants)
		})
	}
}

func TestGuardChainCheckRequiresTheChainWhereItRegisters(t *testing.T) {
	want := buildGuard(4026532001, guardSources, guardExits)
	moved := want
	moved.priority++
	tests := []struct {
		name   string
		chains [][]byte
		wants  string
	}{
		{"the guard chain among the node's", [][]byte{
			guardChainReply(t, unix.NFPROTO_INET, "other", want),
			guardChainReply(t, unix.NFPROTO_INET, guardTableName, want),
		}, ""},
		{"no chain", nil, "is absent"},
		{"another pod's chain", [][]byte{guardChainReply(t, unix.NFPROTO_INET, guardTableName, buildGuard(7, guardSources, guardExits))}, "is absent"},
		{"the chain in another family", [][]byte{guardChainReply(t, unix.NFPROTO_IPV4, guardTableName, want)}, "is absent"},
		{"the chain at another priority", [][]byte{guardChainReply(t, unix.NFPROTO_INET, guardTableName, moved)}, "priority"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftDumps(t, map[uint16][][]byte{unix.NFT_MSG_GETCHAIN: test.chains})
			requireRefusal(t, requireGuardChain(conn, want), test.wants)
		})
	}
}

func TestGuardRuleCheckRequiresTheExpectedRulesInOrder(t *testing.T) {
	want := buildGuard(4026532001, guardSources, guardExits)
	installed := ruleReplies(t, guardTableName, []chain{want})
	reversed := slices.Clone(installed)
	slices.Reverse(reversed)
	tests := []struct {
		name  string
		rules [][]byte
		wants string
	}{
		{"the installed rules", installed, ""},
		{"rules of other tables and chains ignored", append(slices.Clone(installed),
			ruleReply(t, "other", want.name, nil),
			ruleReply(t, guardTableName, "pod-netns-7", nil),
		), ""},
		{"a rule removed", installed[1:], "holds 1 rules, expected 2"},
		{"a rule appended", append(slices.Clone(installed), installed[0]), "holds 3 rules, expected 2"},
		{"the rules out of order", reversed, "expressions of exit guard chain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftDumps(t, map[uint16][][]byte{unix.NFT_MSG_GETRULE: test.rules})
			requireRefusal(t, requireGuardRules(conn, want), test.wants)
		})
	}
}

func TestGuardChecksFailOnAnUnreadableDump(t *testing.T) {
	want := buildGuard(4026532001, guardSources, guardExits)
	chains := func(conn *nfnl.Conn) error { return requireGuardChain(conn, want) }
	rules := func(conn *nfnl.Conn) error { return requireGuardRules(conn, want) }
	truncated := make([]byte, nfgenmsgSize-1)
	tests := []struct {
		name  string
		dump  uint16
		reply []byte // nil refuses the dump itself
		check func(*nfnl.Conn) error
	}{
		{"the table dump is refused", unix.NFT_MSG_GETTABLE, nil, requireGuardTable},
		{"a table reply is truncated", unix.NFT_MSG_GETTABLE, truncated, requireGuardTable},
		{"a table flag is narrower than it reads", unix.NFT_MSG_GETTABLE, nftReply(t, unix.NFPROTO_INET,
			nfnl.Attribute{Type: unix.NFTA_TABLE_FLAGS, Data: []byte{0, 0}},
		), requireGuardTable},
		{"the chain dump is refused", unix.NFT_MSG_GETCHAIN, nil, chains},
		{"a chain reply is truncated", unix.NFT_MSG_GETCHAIN, truncated, chains},
		{"the guard chain's policy is narrower than it reads", unix.NFT_MSG_GETCHAIN, nftReply(t, unix.NFPROTO_INET,
			nfnl.Attribute{Type: unix.NFTA_CHAIN_TABLE, Data: nftName(guardTableName)},
			nfnl.Attribute{Type: unix.NFTA_CHAIN_NAME, Data: nftName(want.name)},
			nfnl.Attribute{Type: unix.NFTA_CHAIN_POLICY, Data: []byte{0, 0}},
		), chains},
		{"a chain attribute is cut short", unix.NFT_MSG_GETCHAIN, append(netfilterHeader(unix.NFPROTO_INET, 0), 8, 0, 1, 0), chains},
		{"the rule dump is refused", unix.NFT_MSG_GETRULE, nil, rules},
		{"a rule reply is truncated", unix.NFT_MSG_GETRULE, truncated, rules},
		{"a rule attribute is cut short", unix.NFT_MSG_GETRULE, append(netfilterHeader(unix.NFPROTO_INET, 0), 8, 0, 1, 0), rules},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := nftError(t, unix.EPERM)
			if test.reply != nil {
				conn = nftDumps(t, map[uint16][][]byte{test.dump: {test.reply}})
			}
			if err := test.check(conn); err == nil || errors.Is(err, ErrMismatch) {
				t.Fatalf("check = %v, want a failure that is no mismatch", err)
			}
		})
	}
}

// guardChainReply encodes c as a chain of table in family, as the kernel
// answers a chain dump.
func guardChainReply(t *testing.T, family byte, table string, c chain) []byte {
	t.Helper()
	hook := marshal(t,
		nfnl.Attribute{Type: unix.NFTA_HOOK_HOOKNUM, Data: binaryutil.BigEndian.PutUint32(uint32(c.hook))},
		nfnl.Attribute{Type: unix.NFTA_HOOK_PRIORITY, Data: binaryutil.BigEndian.PutUint32(uint32(c.priority))},
	)
	return nftReply(t, family,
		nfnl.Attribute{Type: unix.NFTA_CHAIN_TABLE, Data: nftName(table)},
		nfnl.Attribute{Type: unix.NFTA_CHAIN_NAME, Data: nftName(c.name)},
		nfnl.Attribute{Type: unix.NFTA_CHAIN_TYPE, Data: nftName(string(c.kind))},
		nfnl.Attribute{Type: unix.NFTA_CHAIN_POLICY, Data: binaryutil.BigEndian.PutUint32(uint32(c.policy))},
		nfnl.Attribute{Type: unix.NFTA_CHAIN_HOOK | unix.NLA_F_NESTED, Data: hook},
	)
}
