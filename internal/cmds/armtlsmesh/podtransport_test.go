//go:build linux

package armtlsmesh

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/credvolume"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
)

// transportNS keeps its namespace alive on a dedicated thread. Production
// endpoints execute as child processes, so every goroutine inherits that netns.
type transportNS struct {
	path string
	jobs chan func() error
	done chan error
}

func newTransportNS(t *testing.T) *transportNS {
	t.Helper()
	ns := &transportNS{jobs: make(chan func() error), done: make(chan error)}
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ns.done <- err
			return
		}
		ns.path = fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		lo, err := netlink.LinkByName("lo")
		if err == nil {
			err = netlink.LinkSetUp(lo)
		}
		ns.done <- err
		for job := range ns.jobs {
			ns.done <- job()
		}
	}()
	if err := <-ns.done; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(ns.jobs) })
	return ns
}

func (n *transportNS) run(fn func() error) error { n.jobs <- fn; return <-n.done }

func transportLink(t *testing.T, a, b *transportNS, aName, bName, aCIDR, bCIDR string) {
	t.Helper()
	err := a.run(func() error {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: aName}, PeerName: bName}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		peer, err := netlink.LinkByName(bName)
		if err != nil {
			return err
		}
		target, err := netns.GetFromPath(b.path)
		if err != nil {
			return err
		}
		defer target.Close()
		return netlink.LinkSetNsFd(peer, int(target))
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		ns         *transportNS
		name, cidr string
	}{{a, aName, aCIDR}, {b, bName, bCIDR}} {
		if err := side.ns.run(func() error {
			link, err := netlink.LinkByName(side.name)
			if err != nil {
				return err
			}
			addr, err := netlink.ParseAddr(side.cidr)
			if err != nil {
				return err
			}
			if err := netlink.AddrAdd(link, addr); err != nil {
				return err
			}
			return netlink.LinkSetUp(link)
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func transportRoute(t *testing.T, ns *transportNS, gateway string) {
	t.Helper()
	if err := ns.run(func() error { return netlink.RouteAdd(&netlink.Route{Gw: net.ParseIP(gateway)}) }); err != nil {
		t.Fatal(err)
	}
}

func transportVolume(t *testing.T, ca meshCA) meshVolume {
	t.Helper()
	dir, err := os.MkdirTemp("", "c8s-mesh-transport-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	reader, err := credvolume.For(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	volume := meshVolume{Volume: reader, dir: dir, chainName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, 1337, 1337)
	}); err != nil {
		t.Fatal(err)
	}
	return volume
}

func transportCommand(t *testing.T, ns *transportNS, uid int, mode, value string) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("nsenter", "--net="+ns.path, binary, "-test.run=^TestPodTransportProcess$")
	cmd.Env = append(os.Environ(), "C8S_TRANSPORT_MODE="+mode, "C8S_TRANSPORT_VALUE="+value, "C8S_TRANSPORT_UID="+strconv.Itoa(uid))
	return cmd
}

func startTransportProcess(t *testing.T, ns *transportNS, uid int, mode, value string) *exec.Cmd {
	t.Helper()
	cmd := transportCommand(t, ns, uid, mode, value)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatalf("%s failed to start: %s", mode, line)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s startup timed out", mode)
	}
	return cmd
}

// TestPodTransportProcess is a test-binary subprocess, never a network daemon
// in the parent test's namespace. It uses the production original-destination
// getter, credential reader, TLS authentication, and local delivery.
func TestPodTransportProcess(t *testing.T) {
	mode, value := os.Getenv("C8S_TRANSPORT_MODE"), os.Getenv("C8S_TRANSPORT_VALUE")
	if mode == "" {
		return
	}
	uid, err := strconv.Atoi(os.Getenv("C8S_TRANSPORT_UID"))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setgroups(nil); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setgid(uid); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setuid(uid); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "endpoint":
		cfg := &podEndpointConfig{chainPath: filepath.Join(value, "tls.crt"), keyPath: filepath.Join(value, "tls.key"), caPath: filepath.Join(value, "ca.crt")}
		e, err := newPodEndpoint(cfg, discardLogger())
		if err != nil {
			t.Fatal(err)
		}
		listeners, err := e.bind(context.Background(), podOutboundPort, podInboundPort, podHealthPort)
		if err != nil {
			t.Fatal(err)
		}
		e.credentials.reload(time.Now())
		fmt.Println("ready")
		if err := e.serve(context.Background(), listeners); err != nil {
			t.Fatal(err)
		}
	case "echo":
		listener, err := net.Listen("tcp", value)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("ready")
		for {
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	case "client":
		if err := transportEcho(value, nil); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown transport helper %q", mode)
	}
}

func transportEcho(address string, cfg *tls.Config) error {
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if cfg != nil {
		conn = tls.Client(conn, cfg)
	}
	message := "authenticated-pod-transport"
	if _, err := io.WriteString(conn, message); err != nil {
		return err
	}
	answer := make([]byte, len(message))
	if _, err := io.ReadFull(conn, answer); err != nil {
		return err
	}
	if string(answer) != message {
		return fmt.Errorf("unexpected reply %q", answer)
	}
	return nil
}

func TestPodTransportAcrossTwoGuestsInTheNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("C8S_REQUIRE_NFT") == "1" {
			t.Fatal("requires root and network namespace privileges")
		}
		t.Skip("requires root and network namespace privileges")
	}
	if _, err := exec.LookPath("nsenter"); err != nil {
		t.Fatal(err)
	}
	wan, ga, gb, pa, pb := newTransportNS(t), newTransportNS(t), newTransportNS(t), newTransportNS(t), newTransportNS(t)
	transportLink(t, ga, pa, podmesh.GuestBridge, "eth0", "10.255.254.1/30", "10.255.254.2/30")
	transportLink(t, gb, pb, podmesh.GuestBridge, "eth0", "10.255.254.1/30", "10.255.254.2/30")
	transportLink(t, ga, wan, "wan0", "guest-a", "192.0.2.2/24", "192.0.2.1/24")
	transportLink(t, gb, wan, "wan0", "guest-b", "198.51.100.2/24", "198.51.100.1/24")
	transportRoute(t, pa, "10.255.254.1")
	transportRoute(t, pb, "10.255.254.1")
	transportRoute(t, ga, "192.0.2.1")
	transportRoute(t, gb, "198.51.100.1")
	if err := wan.run(installTransportProvider); err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		guest, pod *transportNS
		peer       string
	}{{ga, pa, "203.0.113.1:15006"}, {gb, pb, "203.0.113.2:15001"}} {
		peer := netip.MustParseAddrPort(side.peer)
		destinations := []ruleset.Destination{{Addr: peer.Addr(), Port: peer.Port()}}
		policy := ruleset.Policy{Capture: ruleset.CapturePorts{Outbound: 15001, Inbound: 15006, Health: 15021}, MeshUID: 1337, Pod: &ruleset.PodPolicy{Peers: destinations}}
		if err := ruleset.Install(side.pod.path, policy); err != nil {
			t.Fatal(err)
		}
		guest := ruleset.GuestPolicy{Bridge: podmesh.GuestBridge, PodAddress: podmesh.GuestPodAddress, Peers: destinations, IngressPorts: []uint16{8080}}
		if err := ruleset.InstallGuest(side.guest.path, guest); err != nil {
			t.Fatal(err)
		}
		if err := ruleset.InstallGuest(side.guest.path, guest); err != nil {
			t.Fatalf("reuse: %v", err)
		}
		changed := guest
		changed.IngressPorts = []uint16{8080, 8081}
		if err := ruleset.InstallGuest(side.guest.path, changed); err == nil {
			t.Fatal("guest rules were widened by a retry")
		}
		if err := ruleset.VerifyGuest(side.guest.path, guest); err != nil {
			t.Fatal(err)
		}
		if err := ruleset.Verify(side.pod.path, policy); err != nil {
			t.Fatal(err)
		}
	}
	ca := newMeshCA(t, time.Hour)
	va, vb := transportVolume(t, ca), transportVolume(t, ca)
	startTransportProcess(t, pa, 1500, "echo", "0.0.0.0:8080")
	startTransportProcess(t, pb, 1500, "echo", "0.0.0.0:8080")
	startTransportProcess(t, pa, 1337, "endpoint", va.dir)
	server := startTransportProcess(t, pb, 1337, "endpoint", vb.dir)
	for _, port := range []string{"8400", "8443", "10250"} {
		startTransportProcess(t, ga, 0, "echo", "0.0.0.0:"+port)
		if err := ga.run(func() error { return transportEcho("10.255.254.1:"+port, nil) }); err != nil {
			t.Fatalf("guest service is unavailable: %v", err)
		}
	}
	for _, side := range []struct {
		pod *transportNS
		dst string
	}{{pa, "203.0.113.1:15006"}, {pb, "203.0.113.2:15001"}} {
		if out, err := transportCommand(t, side.pod, 1500, "client", side.dst).CombinedOutput(); err != nil {
			t.Fatalf("mesh %s: %v\n%s", side.dst, err, out)
		}
	}
	// The guest can receive the endpoint's replies to its own readiness probes.
	if err := gb.run(func() error {
		conn, err := net.DialTimeout("tcp", "10.255.254.2:15021", time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = io.WriteString(conn, "GET /readyz HTTP/1.0\r\n\r\n")
		if err != nil {
			return err
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err == nil && !strings.Contains(line, "200") {
			return fmt.Errorf("readiness: %s", line)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	foreign := newMeshCA(t, time.Hour)
	_, foreignTLS := foreign.meshConfigs(t)
	for _, cfg := range []*tls.Config{nil, foreignTLS} {
		if err := ga.run(func() error { return transportEcho("203.0.113.1:15006", cfg) }); err == nil {
			t.Fatal("unauthenticated traffic reached the application")
		}
	}
	for _, uid := range []int{1500, 1337} {
		for _, dst := range []string{"203.0.113.1:15007", "10.255.254.1:8400", "10.255.254.1:8443", "10.255.254.1:10250", "169.254.169.254:80"} {
			if out, err := transportCommand(t, pa, uid, "client", dst).CombinedOutput(); err == nil {
				t.Fatalf("UID %d reached forbidden %s: %s", uid, dst, out)
			}
		}
	}
	if err := server.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = server.Wait()
	withdrawSet(t, vb)
	startTransportProcess(t, pb, 1337, "endpoint", vb.dir)
	if out, err := transportCommand(t, pa, 1500, "client", "203.0.113.1:15006").CombinedOutput(); err == nil {
		t.Fatalf("missing credentials permitted fallback: %s", out)
	}
}

// This is the provider's existing port mapping, outside either protected guest.
func installTransportProvider() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	table := conn.AddTable(&nftables.Table{Name: "provider", Family: nftables.TableFamilyIPv4})
	chain := conn.AddChain(&nftables.Chain{Name: "ingress", Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	for _, mapping := range []struct {
		public, guest string
		port          uint16
	}{{"203.0.113.1", "198.51.100.2", 15006}, {"203.0.113.2", "192.0.2.2", 15001}} {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		address, err := netlink.ParseAddr(mapping.public + "/32")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(lo, address); err != nil {
			return err
		}
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netip.MustParseAddr(mapping.public).AsSlice()},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(mapping.port)},
			&expr.Immediate{Register: 1, Data: netip.MustParseAddr(mapping.guest).AsSlice()}, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(8080)},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2},
		}})
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o600)
}
