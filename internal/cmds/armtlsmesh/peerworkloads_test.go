//go:build linux

package armtlsmesh

import (
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func namedMeshLeaf(t *testing.T, name string, digest byte) leafSpec {
	t.Helper()
	if name == "" {
		return leafSpec{}
	}
	ext, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{
		Name:             name,
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{digest}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return leafSpec{armtlsExt: &ext}
}

func TestOutboundPeerWorkloadPolicy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		local, peer    string
		peerDigest     byte
		malformed      bool
		malformedLocal bool
		allowed        bool
	}{
		{name: "matching workload and policy", local: "router", peer: "worker", peerDigest: 1, allowed: true},
		{name: "wrong workload", local: "router", peer: "other", peerDigest: 1},
		{name: "wrong policy", local: "router", peer: "worker", peerDigest: 2},
		{name: "missing local stamp", peer: "worker", peerDigest: 1},
		{name: "missing peer stamp", local: "router", peerDigest: 1},
		{name: "malformed peer stamp", local: "router", peer: "worker", peerDigest: 1, malformed: true},
		{name: "malformed local stamp", local: "router", peer: "worker", peerDigest: 1, malformedLocal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newMeshCA(t, time.Hour)
			local := namedMeshLeaf(t, tc.local, 1)
			remote := namedMeshLeaf(t, tc.peer, tc.peerDigest)
			if tc.malformedLocal {
				local.armtlsExt = &pkix.Extension{Id: armtls.OIDMatchedWorkload, Value: []byte{5, 0}}
			}
			if tc.malformed {
				remote.armtlsExt = &pkix.Extension{Id: armtls.OIDMatchedWorkload, Value: []byte{5, 0}}
			}
			volume := testVolume(t)
			publishSet(t, volume, ca.issue(t, local))
			peerTLS, _ := ca.meshConfigsFor(t, remote)
			peer := startEchoServer(t, peerTLS)
			_, listeners := startTestEndpoint(t, volume, testPeerAddress, peer.addr(), "worker")
			app, err := net.Dial("tcp", listeners.outbound.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			app.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := app.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			n, err := io.ReadFull(app, buf)
			if tc.allowed {
				if err != nil || string(buf[:n]) != "ping" {
					t.Fatalf("approved peer: received %q, error %v", buf[:n], err)
				}
			} else if n != 0 || err == nil {
				t.Fatalf("caller received %q after refusal, error %v", buf[:n], err)
			}
		})
	}
}

func TestOutboundPeerWorkloadDeliveryOnReconnect(t *testing.T) {
	const request = "synthetic inference request"
	const approvedPolicy, changedPolicy = 1, 2
	for _, hop := range []struct{ caller, requiredPeer string }{
		{"gateway", "sglang-router"},
		{"sglang-router", "custom-inference-worker"},
	} {
		t.Run(hop.caller+"_to_"+hop.requiredPeer, func(t *testing.T) {
			ca := newMeshCA(t, time.Hour)
			volume := testVolume(t)
			publishSet(t, volume, ca.issue(t, namedMeshLeaf(t, hop.caller, approvedPolicy)))
			first := listenForMeshPeer(t)
			replacement := listenForMeshPeer(t)
			var destination atomic.Pointer[net.TCPListener]
			destination.Store(first)
			_, caller := startTestEndpointWithDestination(t, volume, testPeerAddress, func(net.Conn) (string, error) {
				return destination.Load().Addr().String(), nil
			}, hop.requiredPeer)

			approved := namedMeshLeaf(t, hop.requiredPeer, approvedPolicy)
			approved.instanceID = strings.Repeat("1", 64)
			replica := approved
			replica.instanceID = strings.Repeat("2", 64)
			for _, attempt := range []struct {
				name     string
				listener *net.TCPListener
				leaf     leafSpec
				want     string
			}{
				{"approved", first, approved, request},
				{"same address with another workload", first, namedMeshLeaf(t, "other", approvedPolicy), ""},
				{"replacement with membership only", replacement, leafSpec{}, ""},
				{"new connection with another policy", replacement, namedMeshLeaf(t, hop.requiredPeer, changedPolicy), ""},
				{"approved replica", replacement, replica, request},
			} {
				t.Run(attempt.name, func(t *testing.T) {
					serverTLS, _ := ca.meshConfigsFor(t, attempt.leaf)
					destination.Store(attempt.listener)
					sendApplicationRequest(t, caller.outbound, request)
					body, err := readPeerApplicationBytes(t, attempt.listener, serverTLS)
					if err != nil && (attempt.want != "" || errors.Is(err, os.ErrDeadlineExceeded)) {
						t.Fatalf("receiving request: %v", err)
					}
					if string(body) != attempt.want {
						t.Fatalf("peer received %q, want %q", body, attempt.want)
					}
				})
			}
		})
	}
}

func listenForMeshPeer(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func sendApplicationRequest(t *testing.T, outbound net.Listener, request string) {
	t.Helper()
	app, err := net.DialTCP("tcp", nil, outbound.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	if err := app.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(app, request); err != nil {
		t.Fatal(err)
	}
	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

func readPeerApplicationBytes(t *testing.T, listener *net.TCPListener, serverTLS *tls.Config) ([]byte, error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	raw, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	peer := tls.Server(raw, serverTLS)
	defer peer.Close()
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return io.ReadAll(peer)
}
