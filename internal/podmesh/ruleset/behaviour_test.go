//go:build linux

package ruleset

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The UIDs, addresses and ports the behavioural cases use. The pod has one
// veth to a peer namespace, which hosts the resolver, the credential service
// and an address trusted policy names nowhere.
const (
	workloadUID   = 1500
	meshUID       = 1337
	credentialUID = 1338
	plaintextPort = 9000
	servicePort   = 8443
	podAddress    = "10.9.0.1"
	podAddress6   = "fd00:9::1"
	resolver      = "10.9.0.53"
	service       = "10.9.0.43"
	unapproved    = "10.9.0.9"
	unapproved6   = "fd00:9::aa"
	waitFor       = 300 * time.Millisecond
	// firstSourcePort is where the per-case source ports start.
	firstSourcePort = 40000
)

func behaviourPolicy() Policy {
	return Policy{
		Resolver: netip.MustParseAddr(resolver),
		Capture: CapturePorts{
			Outbound: 15001,
			Inbound:  15006,
			Health:   15021,
		},
		MeshUID: meshUID,
		Roles: []Role{{
			UID:          credentialUID,
			Destinations: []Destination{{netip.MustParseAddr(service), servicePort}},
		}},
	}
}

// What the ruleset does to real traffic: application connections are captured
// for the mesh endpoint, a platform role reaches only what it is bound to, the
// resolver exception is the approved address on port 53 with its replies,
// and a socket entering the namespace as root carries nothing. Every case is
// read from the namespace's connection tracking, never from a timeout.
func TestTheRulesetCarriesOnlyPermittedTrafficInTheNamespace(t *testing.T) {
	podNetNS(t, func(netnsPath string) error {
		peer, err := startPeerNamespace()
		if err != nil {
			return err
		}
		defer peer.stop()
		if err := connectPeer(peer); err != nil {
			return err
		}
		policy := behaviourPolicy()
		if err := Install(netnsPath, policy); err != nil {
			return err
		}
		mesh, err := listenAs(meshUID, "127.0.0.1", policy.Capture.Outbound)
		if err != nil {
			return err
		}
		defer mesh.Close()
		go acceptAll(mesh)
		inbound, err := listenAs(meshUID, "0.0.0.0", policy.Capture.Inbound)
		if err != nil {
			return err
		}
		defer inbound.Close()
		go acceptAll(inbound)

		tests := []struct {
			name        string
			uid         uint32
			network     string
			destination string
			want        treatment
		}{
			{"a workload connection is captured", workloadUID, "tcp", address(unapproved, 8080), captured},
			{"the mesh endpoint is not captured", meshUID, "tcp", address(unapproved, 8080), admitted},
			{"a credential role reaches its service", credentialUID, "tcp", address(service, servicePort), admitted},
			{"a credential role reaches nothing else", credentialUID, "tcp", address(unapproved, 8080), denied},
			{"a resolver query is admitted", workloadUID, "udp", address(resolver, 53), admitted},
			{"a resolver query over TCP is admitted", workloadUID, "tcp", address(resolver, 53), admitted},
			{"port 53 elsewhere is captured, not exempted", workloadUID, "tcp", address(unapproved, 53), captured},
			{"a query to another resolver is denied", workloadUID, "udp", address(unapproved, 53), denied},
			{"an IPv6 query to another resolver is denied", workloadUID, "udp", address(unapproved6, 53), denied},
			{"a query to another port is denied", workloadUID, "udp", address(resolver, 5353), denied},
			{"a workload reaches a pod-local port", workloadUID, "tcp", address("127.0.0.1", plaintextPort), admitted},
			{"a namespace entrant reaches nothing", 0, "tcp", address("127.0.0.1", plaintextPort), denied},
		}
		plaintext, err := listenAs(workloadUID, "127.0.0.1", plaintextPort)
		if err != nil {
			return err
		}
		defer plaintext.Close()
		go acceptAll(plaintext)
		// Each case sends from a source port of its own, so the conntrack
		// lookup names that packet and no leftover of another case.
		for i, test := range tests {
			sourcePort := firstSourcePort + uint16(i)
			if err := sendAs(test.uid, test.network, test.destination, sourcePort); err != nil {
				return fmt.Errorf("%s: %w", test.name, err)
			}
			got, err := treatmentOf(policy, test.network, test.destination, sourcePort)
			if err != nil {
				return err
			}
			if got != test.want {
				t.Errorf("%s: traffic was %s, want %s", test.name, got, test.want)
			}
		}

		// The port the server role may leave the cluster on is nothing special
		// to a member pod: a connection arriving on it is captured for the
		// endpoint like any other.
		const routerSourcePort = 40900
		arriving := address(podAddress, serverEgressPort)
		if err := peer.dial(arriving, routerSourcePort); err != nil {
			return err
		}
		got, err := treatmentOf(policy, "tcp", arriving, routerSourcePort)
		if err != nil {
			return err
		}
		if got != captured {
			t.Errorf("a connection arriving on port %d was %s, want captured", serverEgressPort, got)
		}
		return nil
	})
}

// The ports a server role answers on, the identity that reaches the egress
// port outside the cluster and the port it reaches there, and the range of the
// peer's addresses that plays the cluster's own.
const (
	serverUID        = 1339
	serverEgressUID  = 1340
	serverListenPort = 8443
	serverEgressPort = 443
	clusterRange     = "10.9.0.40/29"
)

func serverBehaviourPolicy() Policy {
	policy := behaviourPolicy()
	policy.Server = ServerRole{
		UID:       serverUID,
		Listeners: []uint16{serverListenPort},
		Egress: ServerEgress{
			UID:   serverEgressUID,
			Ports: []uint16{serverEgressPort},
		},
		ClusterRanges: []netip.Prefix{netip.MustParsePrefix(clusterRange)},
	}
	return policy
}

// What the ruleset does to the traffic of a pod that serves a platform role's
// own ports: an external client reaches the port that role answers on, the
// pod's egress identity reaches the egress port outside the cluster in the
// clear, and everything else — the same port inside the cluster, that
// identity's other connections, the role that forwards application traffic,
// and every other identity in the pod — still rides the mesh.
func TestTheServerRoleCarriesOnlyItsOwnPortsInTheNamespace(t *testing.T) {
	podNetNS(t, func(netnsPath string) error {
		peer, err := startPeerNamespace()
		if err != nil {
			return err
		}
		defer peer.stop()
		if err := connectPeer(peer); err != nil {
			return err
		}
		policy := serverBehaviourPolicy()
		if err := Install(netnsPath, policy); err != nil {
			return err
		}
		for _, listener := range []struct {
			uid  uint32
			port uint16
		}{
			{meshUID, policy.Capture.Outbound},
			{meshUID, policy.Capture.Inbound},
			{serverUID, serverListenPort},
		} {
			opened, err := listenAs(listener.uid, "0.0.0.0", listener.port)
			if err != nil {
				return err
			}
			defer opened.Close()
			go acceptAll(opened)
		}

		for _, test := range []struct {
			name       string
			port       uint16
			sourcePort uint16
			want       treatment
		}{
			{"an external client reaches the port the role answers on", serverListenPort, 41000, admitted},
			{"an external client on any other port is captured", plaintextPort, 41001, captured},
		} {
			destination := address(podAddress, test.port)
			if err := peer.dial(destination, test.sourcePort); err != nil {
				return fmt.Errorf("%s: %w", test.name, err)
			}
			got, err := treatmentOf(policy, "tcp", destination, test.sourcePort)
			if err != nil {
				return err
			}
			if got != test.want {
				t.Errorf("%s: traffic was %s, want %s", test.name, got, test.want)
			}
		}

		for _, test := range []struct {
			name        string
			uid         uint32
			destination string
			sourcePort  uint16
			want        treatment
		}{
			{"the egress identity reaches its port outside the cluster", serverEgressUID, address(unapproved, serverEgressPort), 41100, admitted},
			{"the same port inside the cluster is captured", serverEgressUID, address(service, serverEgressPort), 41101, captured},
			{"the egress identity's other connections are captured", serverEgressUID, address(unapproved, 8080), 41102, captured},
			{"the role that forwards application traffic reaches no egress port", serverUID, address(unapproved, serverEgressPort), 41103, captured},
			{"another identity reaches no egress port", workloadUID, address(unapproved, serverEgressPort), 41104, captured},
		} {
			if err := sendAs(test.uid, "tcp", test.destination, test.sourcePort); err != nil {
				return fmt.Errorf("%s: %w", test.name, err)
			}
			got, err := treatmentOf(policy, "tcp", test.destination, test.sourcePort)
			if err != nil {
				return err
			}
			if got != test.want {
				t.Errorf("%s: traffic was %s, want %s", test.name, got, test.want)
			}
		}
		return nil
	})
}

// A reply reaches the pod only when it answers a query the ruleset admitted.
func TestOnlyMatchingResolverRepliesReachThePodInTheNamespace(t *testing.T) {
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
		answered, err := queryResolver(address(resolver, 53))
		if err != nil {
			return err
		}
		if !answered {
			t.Error("a resolver answer did not reach the pod")
		}
		if err := flushConnectionState(); err != nil {
			return err
		}
		if err := peer.inject(address(podAddress, plaintextPort)); err != nil {
			return err
		}
		injected, err := flowOf("udp", address(podAddress, plaintextPort), 53)
		if err != nil {
			return err
		}
		if injected != nil {
			t.Error("an unsolicited reply reached the pod")
		}
		return nil
	})
}

// treatment is what the ruleset did with a packet, as the namespace's
// connection tracking records it.
type treatment string

const (
	denied   treatment = "denied"
	admitted treatment = "admitted"
	captured treatment = "captured"
)

// treatmentOf reads the conntrack entry of one packet: no entry means it never
// left the hooks, a reply tuple from one of the pod's mesh listeners means it
// was redirected to the endpoint, and anything else crossed the pod boundary
// as it was addressed.
func treatmentOf(policy Policy, network, destination string, sourcePort uint16) (treatment, error) {
	flow, err := flowOf(network, destination, sourcePort)
	if err != nil {
		return "", err
	}
	switch {
	case flow == nil:
		return denied, nil
	case redirectedToMesh(flow, policy.Capture.Outbound), redirectedToMesh(flow, policy.Capture.Inbound):
		return captured, nil
	default:
		return admitted, nil
	}
}

// redirectedToMesh reports whether the flow answers from one of the pod's own
// mesh listeners, which is where the capture rules send application traffic.
func redirectedToMesh(flow *netlink.ConntrackFlow, listener uint16) bool {
	return flow.Reverse.SrcPort == listener
}

func flowOf(network, destination string, sourcePort uint16) (*netlink.ConntrackFlow, error) {
	wanted, err := netip.ParseAddrPort(destination)
	if err != nil {
		return nil, err
	}
	family := netlink.InetFamily(unix.AF_INET)
	if wanted.Addr().Is6() {
		family = unix.AF_INET6
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		return nil, fmt.Errorf("list conntrack: %w", err)
	}
	for _, flow := range flows {
		if flow.Forward.Protocol != protocolOf(network) || flow.Forward.DstPort != wanted.Port() || flow.Forward.SrcPort != sourcePort {
			continue
		}
		if address, ok := netip.AddrFromSlice(flow.Forward.DstIP); ok && address.Unmap() == wanted.Addr() {
			return flow, nil
		}
	}
	return nil, nil
}

func protocolOf(network string) uint8 {
	if network == "udp" {
		return unix.IPPROTO_UDP
	}
	return unix.IPPROTO_TCP
}

func flushConnectionState() error {
	if err := netlink.ConntrackTableFlush(netlink.ConntrackTable); err != nil {
		return fmt.Errorf("flush conntrack: %w", err)
	}
	return nil
}

// asUID runs fn with the calling thread's UID set to uid, so a socket fn opens
// carries that UID the way a role container's socket does. The thread is the
// one podNetNS locked and later destroys.
func asUID(uid uint32, fn func() error) (err error) {
	if _, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), 0); errno != 0 {
		return fmt.Errorf("become uid %d: %w", uid, errno)
	}
	defer func() {
		if _, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, 0, 0, 0); errno != 0 && err == nil {
			err = fmt.Errorf("return to uid 0: %w", errno)
		}
	}()
	return fn()
}

// listenAs opens a listener owned by uid at a pod-local address; port 0 takes
// any free port.
func listenAs(uid uint32, host string, port uint16) (net.Listener, error) {
	var listener net.Listener
	err := asUID(uid, func() error {
		opened, err := net.Listen("tcp", address(host, port))
		if err != nil {
			return fmt.Errorf("listen as uid %d: %w", uid, err)
		}
		listener = opened
		return nil
	})
	return listener, err
}

func acceptAll(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}

// sendAs puts one packet on the wire from a named source port. A local refusal
// is not an error here: what the ruleset did is read from connection tracking
// afterwards.
func sendAs(uid uint32, network, destination string, sourcePort uint16) error {
	err := asUID(uid, func() error {
		dialer := net.Dialer{
			Timeout:   waitFor,
			LocalAddr: localAddress(network, sourcePort),
		}
		conn, err := dialer.Dial(network, destination)
		if err != nil {
			return err
		}
		defer conn.Close()
		if network == "udp" {
			_, err = conn.Write([]byte("query"))
		}
		return err
	})
	if err != nil && !deniedLocally(err) {
		return fmt.Errorf("send to %s as uid %d: %w", destination, uid, err)
	}
	return nil
}

// deniedLocally recognises the two ways the ruleset reports a dropped packet
// to its sender: a refused datagram and a connection that never answers.
func deniedLocally(err error) bool {
	var timeout net.Error
	return errors.Is(err, unix.EPERM) || (errors.As(err, &timeout) && timeout.Timeout())
}

// queryResolver sends a query the ruleset admits and reports whether the
// peer's answer came back.
func queryResolver(destination string) (bool, error) {
	var answered bool
	err := asUID(workloadUID, func() error {
		conn, err := net.Dial("udp", destination)
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("query")); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(waitFor)); err != nil {
			return err
		}
		answer := make([]byte, len("answer"))
		if _, err := conn.Read(answer); err != nil {
			return nil
		}
		answered = string(answer) == "answer"
		return nil
	})
	return answered, err
}

func localAddress(network string, port uint16) net.Addr {
	if network == "udp" {
		return &net.UDPAddr{Port: int(port)}
	}
	return &net.TCPAddr{Port: int(port)}
}

func address(host string, port uint16) string {
	return net.JoinHostPort(host, fmt.Sprint(port))
}
