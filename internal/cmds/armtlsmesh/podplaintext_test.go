//go:build linux

package armtlsmesh

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/internal/podmesh/ruleset"
)

// plaintextSink stands for an advertised peer tuple outside the CVM and keeps
// every byte that reaches it: with the mesh in place those are at most an
// armTLS ClientHello, never the application's message.
type plaintextSink struct {
	mu       sync.Mutex
	accepted int
	received []byte
}

func startPlaintextSink(t *testing.T, ns *transportNS, address string) *plaintextSink {
	t.Helper()
	var listener net.Listener
	if err := ns.run(func() (err error) { listener, err = net.Listen("tcp", address); return err }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	sink := &plaintextSink{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				data, _ := io.ReadAll(io.LimitReader(conn, 4096))
				sink.mu.Lock()
				sink.accepted++
				sink.received = append(sink.received, data...)
				sink.mu.Unlock()
			}()
		}
	}()
	return sink
}

func (s *plaintextSink) sawPlaintext(message string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Contains(s.received, []byte(message))
}

func (s *plaintextSink) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// A connection from the pod to an advertised peer tuple rides the mesh or
// fails: with the endpoint stopped, with the pod's capture rules removed and
// with a peer that is no mesh endpoint, the application's bytes never leave the
// CVM in the clear, while another port on the same address stays ordinary
// egress (networking EG5).
func TestPodTransportNeverLeavesPlaintextForAPeerInTheNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("C8S_REQUIRE_NFT") == "1" {
			t.Fatal("requires root and network namespace privileges")
		}
		t.Skip("requires root and network namespace privileges")
	}
	if _, err := exec.LookPath("nsenter"); err != nil {
		t.Fatal(err)
	}
	const message = "authenticated-pod-transport"
	peer := netip.MustParseAddrPort("203.0.113.1:15006")
	for _, failure := range []string{"peer-is-not-a-mesh-endpoint", "endpoint-stopped", "capture-removed"} {
		t.Run(failure, func(t *testing.T) {
			wan, guest, pod := newTransportNS(t), newTransportNS(t), newTransportNS(t)
			transportLink(t, guest, pod, podmesh.GuestBridge, "eth0", "10.255.254.1/30", "10.255.254.2/30")
			transportLink(t, guest, wan, "wan0", "guest-a", "192.0.2.2/24", "192.0.2.1/24")
			transportRoute(t, pod, "10.255.254.1")
			transportRoute(t, guest, "192.0.2.1")
			if err := wan.run(func() error {
				lo, err := netlink.LinkByName("lo")
				if err != nil {
					return err
				}
				address, err := netlink.ParseAddr("203.0.113.1/32")
				if err != nil {
					return err
				}
				return netlink.AddrAdd(lo, address)
			}); err != nil {
				t.Fatal(err)
			}
			destinations := []ruleset.Destination{{Addr: peer.Addr(), Port: peer.Port()}}
			policy := ruleset.Policy{Capture: ruleset.CapturePorts{Outbound: 15001, Inbound: 15006, Health: 15021}, MeshUID: 1337, Pod: &ruleset.PodPolicy{Peers: destinations}}
			if err := ruleset.Install(pod.path, policy); err != nil {
				t.Fatal(err)
			}
			if err := ruleset.InstallGuest(guest.path, ruleset.GuestPolicy{Bridge: podmesh.GuestBridge, PodAddress: podmesh.GuestPodAddress, Peers: destinations, IngressPorts: []uint16{8080}}); err != nil {
				t.Fatal(err)
			}
			ca := newMeshCA(t, time.Hour)
			volume := transportVolume(t, ca)
			endpoint := startGuestMesh(t, guest, pod, volume, "203.0.113.1:15006")
			sink := startPlaintextSink(t, wan, peer.String())
			other := startPlaintextSink(t, wan, "203.0.113.1:15007")
			switch failure {
			case "endpoint-stopped":
				if err := endpoint.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				_ = endpoint.Wait()
			case "capture-removed":
				if err := pod.run(func() error {
					conn, err := nftables.New()
					if err != nil {
						return err
					}
					conn.FlushRuleset()
					return conn.Flush()
				}); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := transportCommand(t, pod, 1500, "client", peer.String()).CombinedOutput(); err == nil {
				t.Fatalf("the application reached the advertised peer outside the mesh: %s", out)
			}
			// Let a connection the sink accepted finish reading before judging it.
			time.Sleep(200 * time.Millisecond)
			if sink.sawPlaintext(message) {
				t.Fatal("application plaintext reached the advertised peer")
			}
			if failure != "peer-is-not-a-mesh-endpoint" && sink.connections() != 0 {
				t.Fatalf("%d connections reached the advertised peer without the mesh", sink.connections())
			}
			// The same address on a port the policy does not advertise is ordinary egress.
			if err := pod.run(func() error {
				conn, err := net.DialTimeout("tcp", "203.0.113.1:15007", time.Second)
				if err != nil {
					return err
				}
				defer conn.Close()
				_, err = io.WriteString(conn, message)
				return err
			}); err != nil {
				t.Fatalf("ordinary egress to a nonpeer port on the peer address failed: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
			if !other.sawPlaintext(message) {
				t.Fatal("ordinary egress to a nonpeer port on the peer address did not arrive")
			}
		})
	}
}
