//go:build linux

package ruleset

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	vishnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	newTable = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWTABLE)
	newChain = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWCHAIN)
	newRule  = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE)
)

// tableDumpReply answers a table dump with the named tables, as the kernel does.
func tableDumpReply(names ...string) nltest.Func {
	return func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 || len(names) == 0 {
			return nil, io.EOF
		}
		reply := make([]netlink.Message, 0, len(names))
		for _, name := range names {
			attrs := nltest.MustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NFTA_TABLE_NAME,
				Data: []byte(name + "\x00"),
			}})
			msg := req[0]
			msg.Header.Type = newTable
			msg.Data = append([]byte{unix.NFPROTO_INET, 0, 0, 0}, attrs...)
			reply = append(reply, msg)
		}
		return nltest.Multipart(reply)
	}
}

// testConn speaks to dial instead of the kernel's netlink socket.
func testConn(t *testing.T, dial nltest.Func) *nftables.Conn {
	t.Helper()
	conn, err := nftables.New(nftables.WithTestDial(dial))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// emptyXtablesLists points the x_tables check at a namespace holding no legacy
// rules, so a case can reach the checks that follow it.
func emptyXtablesLists(t *testing.T) {
	t.Helper()
	writeXtablesLists(t, map[string]string{})
}

func writeXtablesLists(t *testing.T, lists map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range lists {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	previous := xtablesNetDir
	xtablesNetDir = dir
	t.Cleanup(func() {
		xtablesNetDir = previous
	})
}

// Policy no ruleset can be built from is refused before any namespace is
// opened, so a pod is never entered on the strength of policy that is rejected.
func TestInstallRefusesPolicyBeforeOpeningTheNamespace(t *testing.T) {
	policy := testPolicy()
	policy.MeshUID = 0
	err := Install(filepath.Join(t.TempDir(), "absent"), policy)
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("Install error = %v, want %v", err, ErrPolicy)
	}
	if strings.Contains(err.Error(), "network namespace") {
		t.Fatalf("Install reached the namespace: %v", err)
	}
}

// A namespace path the caller cannot open or enter installs nothing: the
// ruleset is not quietly applied to whichever namespace the thread is in.
func TestInstallRefusesAPathThatIsNotANamespace(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "net")
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want string
	}{
		{"absent path", filepath.Join(t.TempDir(), "absent"), "open network namespace"},
		{"regular file", regular, "enter network namespace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Install(test.path, testPolicy())
			if err == nil {
				t.Fatal("Install accepted a path that is not a network namespace")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Install error = %v, want it to mention %q", err, test.want)
			}
		})
	}
}

// The work never runs when the namespace cannot be entered, so it cannot act
// on the caller's own namespace.
func TestInNetNSRunsNothingOutsideTheNamespace(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "net")
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ran := false
	err := inNetNS(regular, func() error {
		ran = true
		return nil
	})
	if err == nil {
		t.Fatal("inNetNS entered a regular file")
	}
	if ran {
		t.Fatal("inNetNS ran its work outside the namespace")
	}
}

// Legacy x_tables rules in the pod namespace are refused: they filter packets
// this ruleset cannot see, and an unreadable list is refused too rather than
// taken for an empty one.
func TestForeignXtablesRulesAreRefused(t *testing.T) {
	tests := []struct {
		name    string
		lists   map[string]string
		foreign bool
		want    string
	}{
		{
			name:  "no lists at all",
			lists: map[string]string{},
		},
		{
			name:  "lists are empty",
			lists: map[string]string{"ip_tables_names": "", "ip6_tables_names": "\n"},
		},
		{
			name:    "IPv4 list holds a table",
			lists:   map[string]string{"ip_tables_names": "nat\nfilter\n"},
			foreign: true,
			want:    "nat,filter",
		},
		{
			name:    "IPv6 list holds a table",
			lists:   map[string]string{"ip6_tables_names": "filter\n"},
			foreign: true,
			want:    "ip6_tables_names",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writeXtablesLists(t, test.lists)
			err := requireNoXtablesRules()
			if !test.foreign {
				if err != nil {
					t.Fatalf("requireNoXtablesRules() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrForeignRules) {
				t.Fatalf("requireNoXtablesRules() = %v, want %v", err, ErrForeignRules)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %v does not mention %q", err, test.want)
			}
		})
	}
}

// A list the thread cannot read is not an empty list.
func TestUnreadableXtablesListIsRefused(t *testing.T) {
	writeXtablesLists(t, map[string]string{})
	if err := os.Mkdir(filepath.Join(xtablesNetDir, "ip_tables_names"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := requireNoXtablesRules()
	if err == nil {
		t.Fatal("requireNoXtablesRules() = nil, want a read error")
	}
	if errors.Is(err, ErrForeignRules) {
		t.Fatalf("requireNoXtablesRules() = %v, want a read error", err)
	}
}

// A namespace already carrying an nftables table is refused by name: a pod is
// protected before its first container runs, so the table is not this policy's.
func TestNamespaceCarryingATableIsRefused(t *testing.T) {
	emptyXtablesLists(t)
	conn := testConn(t, tableDumpReply("someone-elses"))
	err := requireUnprotectedNamespace(conn)
	if !errors.Is(err, ErrForeignRules) {
		t.Fatalf("requireUnprotectedNamespace() = %v, want %v", err, ErrForeignRules)
	}
	if !strings.Contains(err.Error(), "someone-elses") {
		t.Fatalf("error %v does not name the table", err)
	}
}

// A namespace whose tables cannot be listed is refused rather than assumed
// empty.
func TestNamespaceWithUnlistableTablesIsRefused(t *testing.T) {
	emptyXtablesLists(t)
	refused := errors.New("netlink is down")
	conn := testConn(t, func(req []netlink.Message) ([]netlink.Message, error) {
		return nil, refused
	})
	err := requireUnprotectedNamespace(conn)
	if !errors.Is(err, refused) {
		t.Fatalf("requireUnprotectedNamespace() = %v, want %v", err, refused)
	}
	if !strings.Contains(err.Error(), "list nftables tables") {
		t.Fatalf("error %v does not say what failed", err)
	}
}

// The namespace's own connection state decides the outcome: tracked flows or
// state that cannot be read are refused, because a flow admitted before the
// ruleset commits would outlive the rules that admitted it.
func TestConnectionStateDecidesWhetherTheNamespaceIsAccepted(t *testing.T) {
	emptyXtablesLists(t)
	conn := testConn(t, tableDumpReply())
	flows, probe := vishnetlink.ConntrackTableList(vishnetlink.ConntrackTable, unix.AF_INET)
	err := requireUnprotectedNamespace(conn)
	switch {
	case probe != nil:
		if err == nil || !strings.Contains(err.Error(), "list connection state") {
			t.Fatalf("unreadable connection state accepted: %v", err)
		}
	case len(flows) > 0:
		if !errors.Is(err, ErrForeignRules) {
			t.Fatalf("namespace with %d tracked flows gave %v, want %v", len(flows), err, ErrForeignRules)
		}
	default:
		if err != nil {
			t.Fatalf("namespace carrying nothing of its own refused: %v", err)
		}
	}
}

// The whole ruleset is queued as one transaction, so the namespace goes from
// unprotected to fully protected in one commit, with no chain missing its
// rules in between.
func TestQueueRulesetIsOneTransaction(t *testing.T) {
	expected := build(testPolicy())
	wantRules := 0
	for _, c := range expected {
		wantRules += len(c.rules)
	}
	transactions := 0
	var queued []netlink.Message
	conn := testConn(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 { // an acknowledgement read, not a send
			return nil, nil
		}
		transactions++
		queued = append(queued, req...)
		return req, nil
	})
	queueRuleset(conn, expected)
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if transactions != 1 {
		t.Fatalf("queued ruleset in %d transactions, want 1", transactions)
	}
	counts := map[netlink.HeaderType]int{}
	for _, msg := range queued {
		counts[msg.Header.Type]++
	}
	if counts[newTable] != 1 {
		t.Fatalf("queued %d tables, want 1", counts[newTable])
	}
	if counts[newChain] != len(expected) {
		t.Fatalf("queued %d chains, want %d", counts[newChain], len(expected))
	}
	if counts[newRule] != wantRules {
		t.Fatalf("queued %d rules, want %d", counts[newRule], wantRules)
	}
}
