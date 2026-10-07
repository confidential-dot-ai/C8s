//go:build linux

package ruleset

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// ErrForeignRules reports a pod network namespace that already carries packet
// rules or connection state this ruleset cannot account for.
var ErrForeignRules = errors.New("foreign packet state in the pod namespace")

// xtablesNameLists are the legacy x_tables name lists of the IP families: a
// non-empty one means iptables rules no nftables ruleset accounts for.
var xtablesNameLists = []string{"ip_tables_names", "ip6_tables_names"}

// xtablesNetDir is the attached thread's own view of its namespace.
var xtablesNetDir = "/proc/thread-self/net"

// Install puts the ruleset Policy defines into the pod network namespace at
// netnsPath, in a single netlink transaction, once in that namespace's life. A
// pod is protected before its first container runs, so a table, legacy
// x_tables rules or tracked flows already there were not put there by this
// policy, and a flow admitted before the transaction could outlive the rules
// that admitted it.
func Install(netnsPath string, p Policy) error {
	if err := p.validate(); err != nil {
		return err
	}
	expected := build(p)
	return inNetNS(netnsPath, func() error {
		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("open nftables: %w", err)
		}
		if err := requireUnprotectedNamespace(conn); err != nil {
			return err
		}
		queueRuleset(conn, expected)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("install pod ruleset: %w", err)
		}
		return nil
	})
}

// requireUnprotectedNamespace requires a namespace that carries no packet
// rules and no connection state of its own.
func requireUnprotectedNamespace(conn *nftables.Conn) error {
	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("list nftables tables: %w", err)
	}
	if len(tables) > 0 {
		return fmt.Errorf("%w: nftables table %s", ErrForeignRules, tables[0].Name)
	}
	if err := requireNoXtablesRules(); err != nil {
		return err
	}
	return requireNoConnectionState()
}

// requireNoXtablesRules reads the lists through the attached thread, so they
// are the pod namespace's own.
func requireNoXtablesRules() error {
	for _, list := range xtablesNameLists {
		path := xtablesNetDir + "/" + list
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if names := strings.Fields(string(data)); len(names) > 0 {
			return fmt.Errorf("%w: legacy %s holds %s", ErrForeignRules, list, strings.Join(names, ","))
		}
	}
	return nil
}

// requireNoConnectionState requires empty connection tracking, so no flow and
// no expectation outlives the policy that admitted it.
func requireNoConnectionState() error {
	for _, table := range []netlink.ConntrackTableType{netlink.ConntrackTable, netlink.ConntrackExpectTable} {
		for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
			flows, err := netlink.ConntrackTableList(table, family)
			if err != nil {
				return fmt.Errorf("list connection state: %w", err)
			}
			if len(flows) > 0 {
				return fmt.Errorf("%w: %d tracked flows or expectations", ErrForeignRules, len(flows))
			}
		}
	}
	return nil
}

// queueRuleset queues the pod table as one transaction: the namespace is
// protected from the moment it commits.
func queueRuleset(conn *nftables.Conn, expected []chain) {
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: tableName})
	for _, c := range expected {
		hook, priority, policy := c.hook, c.priority, c.policy
		live := conn.AddChain(&nftables.Chain{
			Name:     c.name,
			Table:    table,
			Type:     c.kind,
			Hooknum:  &hook,
			Priority: &priority,
			Policy:   &policy,
		})
		for _, r := range c.rules {
			conn.AddRule(&nftables.Rule{Table: table, Chain: live, Exprs: r.exprs})
		}
	}
}

// inNetNS runs fn on a thread attached to the network namespace at path. The
// thread is never unlocked, so the Go runtime destroys it with the goroutine
// and the attachment cannot leak to other work.
func inNetNS(path string, fn func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		result <- attach(path, fn)
	}()
	return <-result
}

func attach(path string, fn func() error) error {
	target, err := netns.GetFromPath(path)
	if err != nil {
		return fmt.Errorf("open network namespace %s: %w", path, err)
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		return fmt.Errorf("enter network namespace %s: %w", path, err)
	}
	return fn()
}
