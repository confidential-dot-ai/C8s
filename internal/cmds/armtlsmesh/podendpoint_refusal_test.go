//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// newIdleEndpoint is an endpoint whose handlers a test drives directly, with
// the captured destination the kernel would have recorded.
func newIdleEndpoint(t *testing.T, volume credentialVolume, own podAddresses, origDst origDstFunc) *podEndpoint {
	t.Helper()
	e := &podEndpoint{
		credentials: &credentials{
			volume: volume,
			logger: discardLogger(),
		},
		own:     own,
		origDst: origDst,
		logger:  discardLogger(),
		bufPool: newBufPool(0),
	}
	e.credentials.reload(time.Now())
	return e
}

// withdrawOnWrite withdraws the adopted generation while the handshake it
// carries is still in flight.
type withdrawOnWrite struct {
	net.Conn
	creds *credentials
	once  sync.Once
}

func (c *withdrawOnWrite) Write(b []byte) (int, error) {
	c.once.Do(func() {
		c.creds.withdraw(errors.New("the test withdrew the generation"))
	})
	return c.Conn.Write(b)
}

// closedPort is an address nothing listens on, as a destination the kernel
// recorded before the application stopped listening.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// A connection whose original destination the kernel does not report is
// refused: the endpoint never guesses where captured bytes were going.
func TestHandlersRefuseAConnectionWithoutAnOriginalDestination(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	unavailable := func(net.Conn) (string, error) {
		return "", errors.New("conntrack holds no entry for this connection")
	}
	e := newIdleEndpoint(t, volume, testPodAddress, unavailable)

	for name, handle := range map[string]func(context.Context, net.Conn){
		"outbound": e.handleOutbound,
		"inbound":  e.handleInbound,
	} {
		t.Run(name, func(t *testing.T) {
			app, endpointSide := net.Pipe()
			defer app.Close()
			handle(context.Background(), endpointSide)
			endpointSide.Close()
			if data, _ := io.ReadAll(app); len(data) != 0 {
				t.Fatalf("the refused connection answered %q", data)
			}
		})
	}
}

// The destination exclusions hold on the handlers, not only on the predicates:
// a captured connection to the pod's own address is never dialled, and inbound
// mesh bytes are never delivered off the pod.
func TestHandlersRefuseAnExcludedDestination(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))

	tests := []struct {
		name   string
		own    podAddresses
		handle func(*podEndpoint) func(context.Context, net.Conn)
	}{
		{"captured destination inside the pod", testPodAddress, func(e *podEndpoint) func(context.Context, net.Conn) {
			return e.handleOutbound
		}},
		{"mesh delivery outside the pod", testPeerAddress, func(e *podEndpoint) func(context.Context, net.Conn) {
			return e.handleInbound
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := startEchoServer(t, nil)
			e := newIdleEndpoint(t, volume, tc.own, func(net.Conn) (string, error) {
				return app.addr(), nil
			})
			peer, endpointSide := net.Pipe()
			defer peer.Close()
			tc.handle(e)(context.Background(), endpointSide)
			endpointSide.Close()
			if delivered := app.delivered.Load(); delivered != 0 {
				t.Fatalf("%d connections reached %s", delivered, app.addr())
			}
		})
	}
}

// A generation withdrawn while the handshake runs costs the connection: the
// endpoint forwards nothing it cannot authenticate under published credentials.
func TestOutboundRefusesToForwardWhenTheGenerationIsWithdrawn(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	peerTLS, _ := ca.meshConfigs(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	e := newIdleEndpoint(t, volume, testPeerAddress, func(net.Conn) (string, error) {
		return ln.Addr().String(), nil
	})

	carried := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			carried <- -1
			return
		}
		defer conn.Close()
		// The withdrawal lands before the endpoint's dial returns.
		e.credentials.withdraw(errors.New("the test withdrew the generation"))
		server := tls.Server(conn, peerTLS)
		if err := server.Handshake(); err != nil {
			carried <- -1
			return
		}
		if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			carried <- -1
			return
		}
		data, _ := io.ReadAll(server)
		carried <- len(data)
	}()

	app, endpointSide := net.Pipe()
	defer app.Close()
	go func() {
		_, _ = app.Write([]byte("ping"))
	}()
	e.handleOutbound(context.Background(), endpointSide)
	endpointSide.Close()
	if got := <-carried; got > 0 {
		t.Fatalf("the peer received %d application bytes after the withdrawal", got)
	}
}

// The same holds on delivery: an authenticated peer whose generation went away
// mid-handshake reaches no application socket.
func TestInboundRefusesToDeliverWhenTheGenerationIsWithdrawn(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	_, clientTLS := ca.meshConfigs(t)
	app := startEchoServer(t, nil)
	e := newIdleEndpoint(t, volume, testPodAddress, func(net.Conn) (string, error) {
		return app.addr(), nil
	})

	peerSide, endpointSide := net.Pipe()
	handshaken := make(chan error, 1)
	go func() {
		client := tls.Client(peerSide, clientTLS)
		handshaken <- client.HandshakeContext(context.Background())
	}()
	withdrawing := &withdrawOnWrite{
		Conn:  endpointSide,
		creds: e.credentials,
	}
	e.handleInbound(context.Background(), withdrawing)
	endpointSide.Close()
	peerSide.Close()
	if err := <-handshaken; err != nil {
		t.Fatalf("the peer did not authenticate: %v", err)
	}
	if delivered := app.delivered.Load(); delivered != 0 {
		t.Fatalf("%d connections reached the application after the withdrawal", delivered)
	}
}

// An application that is not listening costs the mesh connection and nothing
// else.
func TestDeliverLocalRefusesAClosedApplicationPort(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	e := newIdleEndpoint(t, volume, testPodAddress, func(net.Conn) (string, error) {
		return "", errors.New("unused")
	})

	peer, endpointSide := net.Pipe()
	defer peer.Close()
	e.deliverLocal(context.Background(), endpointSide, netip.MustParseAddrPort(closedPort(t)), discardLogger())
	endpointSide.Close()
	if data, _ := io.ReadAll(peer); len(data) != 0 {
		t.Fatalf("the undeliverable connection answered %q", data)
	}
}

// A listener that fails outside cancellation stops the endpoint, rather than
// spinning on a port it no longer owns.
func TestAcceptReportsAListenerFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	e := &podEndpoint{logger: discardLogger()}
	handled := func(context.Context, net.Conn) {
		t.Error("a connection was handled on a closed listener")
	}
	if err := e.accept(context.Background(), ln, handled); err == nil {
		t.Fatal("accept returned no error on a closed listener")
	}
}
