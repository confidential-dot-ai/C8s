//go:build linux

package ruleset

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// requireNamespace fails rather than skips when C8S_REQUIRE_NFT is set, which
// is how CI runs these tests: a namespace it cannot create must not leave the
// pod ruleset silently untested.
func requireNamespace(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	const reason = "needs uid 0 in its network namespace: run under sudo or unshare -Urn"
	if os.Getenv("C8S_REQUIRE_NFT") == "1" {
		t.Fatal(reason)
	}
	t.Skip(reason)
}

// podNetNS runs fn attached to a network namespace of its own, passing the
// namespace path a host-side caller holds for a pod. fn runs on the attached
// thread, so the sockets it opens are the pod's.
func podNetNS(t *testing.T, fn func(netnsPath string) error) {
	t.Helper()
	requireNamespace(t)
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with this goroutine
		result <- inOwnNetNS(fn)
	}()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func inOwnNetNS(fn func(netnsPath string) error) error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("create network namespace: %w", err)
	}
	if err := linkUp("lo"); err != nil {
		return err
	}
	return fn(ownNetNSPath())
}

func ownNetNSPath() string {
	return fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
}

func linkUp(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find link %s: %w", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up link %s: %w", name, err)
	}
	return nil
}

// The golden file claims to be nft's own syntax, so nft must accept it as input.
func TestTheGoldenRulesetIsNFTInputInTheNamespace(t *testing.T) {
	podNetNS(t, func(string) error {
		out, err := exec.Command("nft", "--check", "--file", "testdata/ruleset.golden").CombinedOutput()
		if err != nil {
			t.Errorf("nft --check testdata/ruleset.golden: %v\n%s", err, out)
		}
		return nil
	})
}

// A pod is protected before its first container runs, so a namespace that
// already carries rules or tracked flows is not the fresh namespace this
// install is for.
func TestInstallRefusesAUsedNamespaceInTheNamespace(t *testing.T) {
	t.Run("rules already installed", func(t *testing.T) {
		podNetNS(t, func(netnsPath string) error {
			if err := Install(netnsPath, testPolicy()); err != nil {
				return err
			}
			if err := Install(netnsPath, testPolicy()); !errors.Is(err, ErrForeignRules) {
				t.Errorf("second install = %v, want ErrForeignRules", err)
			}
			return nil
		})
	})
	t.Run("flows already tracked", func(t *testing.T) {
		podNetNS(t, func(netnsPath string) error {
			if err := Install(netnsPath, testPolicy()); err != nil {
				return err
			}
			closeFlow, err := establishLoopbackFlow()
			if err != nil {
				return err
			}
			defer closeFlow()
			if err := deletePodTable(); err != nil {
				return err
			}
			err = Install(netnsPath, testPolicy())
			if !errors.Is(err, ErrForeignRules) {
				t.Errorf("install over tracked flows = %v, want ErrForeignRules", err)
			} else if !strings.Contains(err.Error(), "tracked flows") {
				t.Errorf("install over tracked flows = %v, want the tracked flows named", err)
			}
			return nil
		})
	})
	t.Run("legacy rules present", func(t *testing.T) {
		netDir := t.TempDir()
		if err := os.WriteFile(netDir+"/ip_tables_names", []byte("filter\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		previous := xtablesNetDir
		xtablesNetDir = netDir
		t.Cleanup(func() { xtablesNetDir = previous })
		podNetNS(t, func(netnsPath string) error {
			if err := Install(netnsPath, testPolicy()); !errors.Is(err, ErrForeignRules) {
				t.Errorf("install over legacy rules = %v, want ErrForeignRules", err)
			}
			return nil
		})
	})
}

// One expected ruleset covers every pod on a node, so the rules the kernel
// holds must not mention the address this pod happens to have.
func TestInstalledRulesCarryNoPodAddressInTheNamespace(t *testing.T) {
	podNetNS(t, func(netnsPath string) error {
		peer, err := startPeerNamespace()
		if err != nil {
			return err
		}
		defer peer.stop()
		if err := connectPeer(peer); err != nil {
			return err
		}
		if err := Install(netnsPath, behaviourPolicy()); err != nil {
			return err
		}
		addresses, err := podAddresses()
		if err != nil {
			return err
		}
		if len(addresses) == 0 {
			return errors.New("the pod namespace has no address of its own to look for")
		}
		rules, err := installedRules()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			if strings.Contains(rules, address) {
				t.Errorf("the installed rules carry the pod address %s", address)
			}
		}
		return nil
	})
}

// podAddresses are the addresses the namespace holds, which no rule may carry.
func podAddresses() ([]string, error) {
	link, err := netlink.LinkByName("pod0")
	if err != nil {
		return nil, fmt.Errorf("find link pod0: %w", err)
	}
	var addresses []string
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		assigned, err := netlink.AddrList(link, family)
		if err != nil {
			return nil, fmt.Errorf("list addresses: %w", err)
		}
		for _, address := range assigned {
			addresses = append(addresses, address.IP.String())
		}
	}
	return addresses, nil
}

// installedRules renders the rules the kernel holds, the way the golden file
// renders the expected ones.
func installedRules() (string, error) {
	conn, err := nftables.New()
	if err != nil {
		return "", err
	}
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return "", fmt.Errorf("list chains: %w", err)
	}
	var rendered strings.Builder
	for _, c := range chains {
		rules, err := conn.GetRules(table, c)
		if err != nil {
			return "", fmt.Errorf("list rules of chain %s: %w", c.Name, err)
		}
		for _, r := range rules {
			fmt.Fprintln(&rendered, nftRule(r.Exprs))
		}
	}
	return rendered.String(), nil
}

func deletePodTable() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("delete the pod table: %w", err)
	}
	return nil
}

// establishLoopbackFlow opens a tracked connection between two sockets of the
// pod, which plaintext between containers of one pod is allowed to be.
func establishLoopbackFlow() (func(), error) {
	listener, err := listenAs(workloadUID, "127.0.0.1", 0)
	if err != nil {
		return nil, err
	}
	var client net.Conn
	err = asUID(workloadUID, func() error {
		opened, err := net.DialTimeout("tcp", listener.Addr().String(), waitFor)
		client = opened
		return err
	})
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("dial: %w", err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		listener.Close()
		return nil, fmt.Errorf("accept: %w", err)
	}
	return func() {
		server.Close()
		client.Close()
		listener.Close()
	}, nil
}
