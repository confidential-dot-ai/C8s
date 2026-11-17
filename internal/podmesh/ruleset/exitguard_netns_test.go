//go:build linux

package ruleset

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

// The exit the guard cases grant: a Service the control plane publishes on
// translatedExit is translated by the node to a service on the node's own
// address, while directExit is reached as dialed.
const (
	exitPort       = 443
	translatedExit = "203.0.113.7"
	directExit     = "203.0.113.8"
)

var guardedExits = []Exit{{netip.MustParsePrefix("203.0.113.0/24"), exitPort}}

// kubeProxyStandIn is the translation kube-proxy installs for a Service with
// an externalIP inside the pod's exit and its endpoint on the node.
var kubeProxyStandIn = fmt.Sprintf(`table ip kube-proxy-stand-in {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		ip daddr %s tcp dport %d dnat to %s:%d
	}
}`, translatedExit, exitPort, service, servicePort)

// A connection through an exit that the node translates elsewhere is dropped
// once the pod's exit guard is installed; one the node carries as dialed is
// not. Both reach their listener before the guard, so neither result is a
// broken setup.
func TestTheExitGuardDropsATranslatedExitInTheNamespace(t *testing.T) {
	podNetNS(t, func(podPath string) error {
		node, err := exitNode(t)
		if err != nil {
			return err
		}
		defer node.stop()
		for _, destination := range []string{translatedExit, directExit} {
			if err := dialExit(destination); err != nil {
				t.Fatalf("before the guard, dial %s = %v, want a connection", destination, err)
			}
		}

		if err := GuardExits(node.path, podPath, guardedExits); err != nil {
			return err
		}
		if err := dialExit(translatedExit); err == nil {
			t.Errorf("dial %s with the guard = connected, want dropped", translatedExit)
		}
		if err := dialExit(directExit); err != nil {
			t.Errorf("dial %s with the guard = %v, want a connection", directExit, err)
		}
		return nil
	})
}

// The guard verifies against what GuardExits installed and nothing else:
// other exits, an added rule, a released chain and a dormant table are each
// refused.
func TestVerifyExitGuardInTheNamespace(t *testing.T) {
	podNetNS(t, func(podPath string) error {
		node, err := exitNode(t)
		if err != nil {
			return err
		}
		defer node.stop()
		if err := VerifyExitGuard(node.path, podPath, guardedExits); !errors.Is(err, ErrMismatch) {
			t.Errorf("VerifyExitGuard before GuardExits = %v, want ErrMismatch", err)
		}
		if err := GuardExits(node.path, podPath, guardedExits); err != nil {
			return err
		}
		if err := GuardExits(node.path, podPath, guardedExits); err != nil {
			t.Errorf("GuardExits again = %v, want the same chain verified", err)
		}
		other := []Exit{{netip.MustParsePrefix("198.51.100.0/24"), exitPort}}
		if err := VerifyExitGuard(node.path, podPath, other); !errors.Is(err, ErrMismatch) {
			t.Errorf("VerifyExitGuard(%v) = %v, want ErrMismatch", other, err)
		}

		if err := node.run(func() error { return widenGuard(&expr.Verdict{Kind: expr.VerdictAccept}) }); err != nil {
			return err
		}
		requireMismatch(t, VerifyExitGuard(node.path, podPath, guardedExits), "holds 2 rules")

		if err := GuardExits(node.path, podPath, guardedExits); err != nil {
			return err
		}
		inode, err := readNamespaceInode(podPath)
		if err != nil {
			return err
		}
		if err := ReleaseExitGuard(node.path, inode); err != nil {
			return err
		}
		requireMismatch(t, VerifyExitGuard(node.path, podPath, guardedExits), "is absent")
		if err := ReleaseExitGuard(node.path, inode); err != nil {
			t.Errorf("ReleaseExitGuard of a released guard = %v, want nil", err)
		}

		if err := GuardExits(node.path, podPath, guardedExits); err != nil {
			return err
		}
		if err := node.run(func() error { return nftInput("add table inet " + guardTableName + " { flags dormant; }") }); err != nil {
			return err
		}
		requireMismatch(t, VerifyExitGuard(node.path, podPath, guardedExits), "table flags")
		return nil
	})
}

func TestGuardExitsRefusesWhatItCannotGuardInTheNamespace(t *testing.T) {
	podNetNS(t, func(podPath string) error {
		node, err := startPeerNamespace()
		if err != nil {
			return err
		}
		defer node.stop()
		if err := GuardExits(node.path, podPath, guardedExits); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "no address") {
			t.Errorf("GuardExits for a pod with no address = %v, want ErrPolicy naming the address", err)
		}
		if err := GuardExits(node.path, podPath, nil); !errors.Is(err, ErrPolicy) {
			t.Errorf("GuardExits(nil) = %v, want ErrPolicy", err)
		}
		hostBits := []Exit{{netip.PrefixFrom(netip.MustParseAddr(translatedExit), 24), exitPort}}
		if err := GuardExits(node.path, podPath, hostBits); !errors.Is(err, ErrPolicy) {
			t.Errorf("GuardExits(%v) = %v, want ErrPolicy", hostBits, err)
		}
		return nil
	})
}

// exitNode connects the pod to a node namespace that routes the exit range to
// itself, answers on directExit and the service address, and translates
// translatedExit the way kube-proxy does. It runs on the pod's thread.
func exitNode(t *testing.T) (*peerNamespace, error) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("the kube-proxy stand-in needs nft")
	}
	node, err := startPeerNamespace()
	if err != nil {
		return nil, err
	}
	if err := connectPeer(node); err != nil {
		node.stop()
		return nil, err
	}
	gateway := netip.MustParseAddr(unapproved).AsSlice()
	if err := netlink.RouteAdd(&netlink.Route{Gw: gateway}); err != nil {
		node.stop()
		return nil, fmt.Errorf("route the pod through the node: %w", err)
	}
	err = node.run(func() error {
		if err := addAddresses("node0", []string{directExit + "/32"}); err != nil {
			return err
		}
		listener, err := net.Listen("tcp", address(directExit, exitPort))
		if err != nil {
			return err
		}
		node.listeners = append(node.listeners, listener)
		go acceptAll(listener)
		return nftInput(kubeProxyStandIn)
	})
	if err != nil {
		node.stop()
		return nil, err
	}
	return node, nil
}

func dialExit(destination string) error {
	conn, err := net.DialTimeout("tcp", address(destination, exitPort), waitFor)
	if err != nil {
		return err
	}
	return conn.Close()
}

func nftInput(ruleset string) error {
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(ruleset)
	if out, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %w: %s", err, out)
	}
	return nil
}

// widenGuard appends a rule to the attached namespace's only guard chain.
func widenGuard(added expr.Any) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	for _, c := range chains {
		if c.Table.Name == guardTableName {
			conn.AddRule(&nftables.Rule{Table: c.Table, Chain: c, Exprs: []expr.Any{added}})
			return conn.Flush()
		}
	}
	return errors.New("no exit guard chain")
}
