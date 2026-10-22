//go:build linux

package ruleset

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// The isolated ruleset has no conntrack expressions to activate tracking in a
// fresh namespace. These probes therefore check TCP handshakes and UDP replies,
// then require the same endpoints to respond after removing the isolation table.
func TestIsolatedPodCarriesOnlyLocalTrafficInTheNamespace(t *testing.T) {
	podNetNS(t, func(netnsPath string) error {
		peer, err := startPeerNamespace()
		if err != nil {
			return err
		}
		defer peer.stop()
		if err := connectPeer(peer); err != nil {
			return err
		}
		// The shared peer already serves IPv4 TCP and DNS. Give the IPv6
		// controls the same live listeners, so missing services cannot pass.
		var resolver6 *net.UDPConn
		if err := peer.run(func() error {
			for _, port := range []uint16{8080, resolverPort} {
				listener, err := net.Listen("tcp", address(unapproved6, port))
				if err != nil {
					return err
				}
				peer.listeners = append(peer.listeners, listener)
				go acceptAll(listener)
			}
			opened, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(unapproved6), Port: resolverPort})
			if err != nil {
				return err
			}
			resolver6 = opened
			go answerQueries(resolver6)
			return nil
		}); err != nil {
			return err
		}
		defer resolver6.Close()
		policy := Policy{Isolated: true}
		if err := Install(netnsPath, policy); err != nil {
			return err
		}
		if err := Verify(netnsPath, policy); err != nil {
			return err
		}
		for _, host := range []string{"127.0.0.1", "::1", podAddress, podAddress6} {
			listener, err := listenAs(workloadUID, host, plaintextPort)
			if err != nil {
				return err
			}
			defer listener.Close()
			go acceptAll(listener)
		}
		tests := []struct {
			name        string
			uid         uint32
			network     string
			destination string
			local       bool
		}{
			{"IPv4 loopback", workloadUID, "tcp", address("127.0.0.1", plaintextPort), true},
			{"IPv6 loopback", workloadUID, "tcp", address("::1", plaintextPort), true},
			{"pod IPv4 address", workloadUID, "tcp", address(podAddress, plaintextPort), true},
			{"pod IPv6 address", workloadUID, "tcp", address(podAddress6, plaintextPort), true},
			{"root namespace entrant IPv4", 0, "tcp", address("127.0.0.1", plaintextPort), false},
			{"root namespace entrant IPv6", 0, "tcp", address("::1", plaintextPort), false},
			{"guest service", workloadUID, "tcp", address(service, servicePort), false},
			{"IPv4 remote", workloadUID, "tcp", address(unapproved, 8080), false},
			{"IPv6 remote", workloadUID, "tcp", address(unapproved6, 8080), false},
			{"mesh UID has no exception", meshUID, "tcp", address(unapproved, 8080), false},
			{"credential UID has no exception", credentialUID, "tcp", address(service, servicePort), false},
			{"IPv4 DNS TCP", workloadUID, "tcp", address(resolver, resolverPort), false},
			{"IPv4 DNS UDP", workloadUID, "udp", address(resolver, resolverPort), false},
			{"IPv6 DNS TCP", workloadUID, "tcp", address(unapproved6, resolverPort), false},
			{"IPv6 DNS UDP", workloadUID, "udp", address(unapproved6, resolverPort), false},
		}
		for phase, isolated := range []bool{true, false} {
			if !isolated {
				if err := deletePodTable(); err != nil {
					return err
				}
				if err := Verify(netnsPath, policy); !errors.Is(err, ErrMismatch) {
					return fmt.Errorf("verify removed isolation = %v, want ErrMismatch", err)
				}
			}
			for i, test := range tests {
				sourcePort := firstSourcePort + uint16(phase*100+i)
				got, err := probeIsolatedTraffic(test.uid, test.network, test.destination, sourcePort)
				if err != nil {
					return fmt.Errorf("%s (isolated=%t): %w", test.name, isolated, err)
				}
				want := !isolated || test.local
				if got != want {
					t.Errorf("%s (isolated=%t): connected = %t, want %t", test.name, isolated, got, want)
				}
			}
			for i, host := range []string{podAddress, podAddress6} {
				if err := peer.run(func() error {
					sourcePort := uint16(42000 + phase*100 + i)
					got, err := probeIsolatedTraffic(0, "tcp", address(host, plaintextPort), sourcePort)
					if err != nil {
						return err
					}
					if got == isolated {
						t.Errorf("inbound to %s (isolated=%t): connected = %t, want %t", host, isolated, got, !isolated)
					}
					return nil
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// probeIsolatedTraffic succeeds only when the destination actually answers.
// Each phase uses distinct source ports so a previous flow cannot satisfy it.
func probeIsolatedTraffic(uid uint32, network, destination string, sourcePort uint16) (bool, error) {
	connected := false
	err := asUID(uid, func() error {
		dialer := net.Dialer{Timeout: waitFor, LocalAddr: localAddress(network, sourcePort)}
		conn, err := dialer.Dial(network, destination)
		if err != nil {
			return err
		}
		defer conn.Close()
		if network == "udp" {
			if err := conn.SetDeadline(time.Now().Add(waitFor)); err != nil {
				return err
			}
			if _, err := conn.Write([]byte("query")); err != nil {
				return err
			}
			answer := make([]byte, len("answer"))
			if _, err := conn.Read(answer); err != nil {
				return err
			}
			if string(answer) != "answer" {
				return fmt.Errorf("unexpected resolver reply %q", answer)
			}
		}
		connected = true
		return nil
	})
	if err != nil && !deniedLocally(err) {
		return false, err
	}
	return connected, nil
}
