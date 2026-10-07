//go:build linux

package ruleset

import (
	"fmt"
	"net"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// peerAddresses are the addresses the node side of the veth answers on: the
// two resolvers, the credential service, and two addresses trusted policy
// names nowhere.
var peerAddresses = []string{resolver + "/24", service + "/24", unapproved + "/24", resolver6 + "/64", unapproved6 + "/64"}

// peerServices are the ports the peer accepts on, so traffic the ruleset
// admits completes instead of waiting.
var peerServices = []string{address(service, servicePort), address(resolver, 53), address(unapproved, 8080), address(unapproved, 53)}

// peerNamespace is the node side of the pod's veth: the resolver, the
// credential service and the addresses outside trusted policy all live here,
// where the pod's rules do not apply. Work runs on its own attached thread,
// because a socket belongs to the namespace of the thread that opened it.
type peerNamespace struct {
	path     string
	work     chan func() error
	finished chan error
	resolver map[string]*net.UDPConn
}

func startPeerNamespace() (*peerNamespace, error) {
	peer := &peerNamespace{
		work:     make(chan func() error),
		finished: make(chan error, 1),
		resolver: map[string]*net.UDPConn{},
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with this goroutine
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- fmt.Errorf("create peer namespace: %w", err)
			return
		}
		peer.path = ownNetNSPath()
		ready <- linkUp("lo")
		for job := range peer.work {
			peer.finished <- job()
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return peer, nil
}

func (p *peerNamespace) run(job func() error) error {
	p.work <- job
	return <-p.finished
}

func (p *peerNamespace) stop() {
	close(p.work)
}

// inject sends an answer the pod never asked for.
func (p *peerNamespace) inject(destination string) error {
	target, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		return err
	}
	_, err = p.resolver[resolver].WriteToUDP([]byte("answer"), target)
	return err
}

// connectPeer gives the pod one veth to the peer namespace and starts the
// services the behavioural cases talk to. It runs on the pod's thread.
func connectPeer(peer *peerNamespace) error {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "pod0"}, PeerName: "node0"}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("add veth: %w", err)
	}
	target, err := netns.GetFromPath(peer.path)
	if err != nil {
		return err
	}
	defer target.Close()
	node, err := netlink.LinkByName("node0")
	if err != nil {
		return fmt.Errorf("find link node0: %w", err)
	}
	if err := netlink.LinkSetNsFd(node, int(target)); err != nil {
		return fmt.Errorf("move node0 to the peer namespace: %w", err)
	}
	if err := addAddresses("pod0", []string{podAddress + "/24", podAddress6 + "/64"}); err != nil {
		return err
	}
	if err := linkUp("pod0"); err != nil {
		return err
	}
	return peer.run(func() error {
		if err := addAddresses("node0", peerAddresses); err != nil {
			return err
		}
		if err := linkUp("node0"); err != nil {
			return err
		}
		return peer.startServices()
	})
}

// startServices opens the peer's sockets on its own thread and leaves ordinary
// goroutines to serve them: a socket keeps the namespace it was opened in.
func (p *peerNamespace) startServices() error {
	for _, service := range peerServices {
		listener, err := net.Listen("tcp", service)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", service, err)
		}
		go acceptAll(listener)
	}
	for _, host := range []string{resolver, resolver6} {
		answering, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: 53})
		if err != nil {
			return fmt.Errorf("serve DNS on %s: %w", host, err)
		}
		p.resolver[host] = answering
		go answerQueries(answering)
	}
	return nil
}

func answerQueries(conn *net.UDPConn) {
	query := make([]byte, 512)
	for {
		read, from, err := conn.ReadFromUDP(query)
		if err != nil {
			return
		}
		if read == 0 {
			continue
		}
		if _, err := conn.WriteToUDP([]byte("answer"), from); err != nil {
			return
		}
	}
}

func addAddresses(link string, addresses []string) error {
	device, err := netlink.LinkByName(link)
	if err != nil {
		return fmt.Errorf("find link %s: %w", link, err)
	}
	for _, address := range addresses {
		parsed, err := netlink.ParseAddr(address)
		if err != nil {
			return err
		}
		parsed.Flags = unix.IFA_F_NODAD // no duplicate-address wait on a point-to-point veth
		if err := netlink.AddrAdd(device, parsed); err != nil {
			return fmt.Errorf("add %s to %s: %w", address, link, err)
		}
	}
	return nil
}
