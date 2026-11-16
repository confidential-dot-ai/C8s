//go:build linux

package armtlsmesh

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// unanswered is an address nothing listens on, so a dial to it is refused
// rather than left to the dial timeout.
func unanswered(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// A captured connection whose original destination is inside the pod is
// refused rather than carried back in.
func TestOutboundRefusesADestinationInsideThePod(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	app := startEchoServer(t, nil)
	_, listeners := startTestEndpoint(t, volume, testPodAddress, app.addr())

	conn, err := net.Dial("tcp", listeners.outbound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertClosedWithoutData(t, conn)
	if delivered := app.delivered.Load(); delivered != 0 {
		t.Fatalf("%d connections reached the destination", delivered)
	}
}

// A destination that answers no dial costs the captured connection and
// nothing else.
func TestOutboundRefusesADestinationThatDoesNotAnswer(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	_, listeners := startTestEndpoint(t, volume, testPeerAddress, unanswered(t))

	conn, err := net.Dial("tcp", listeners.outbound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertClosedWithoutData(t, conn)
}

// An inbound mesh connection captured for an address the pod does not hold is
// refused before the handshake, so nothing is delivered off the pod.
func TestInboundRefusesADestinationOutsideThePod(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	_, listeners := startTestEndpoint(t, volume, testPodAddress, "10.42.0.9:8080")

	conn, err := net.Dial("tcp", listeners.inbound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertClosedWithoutData(t, conn)
}

// An authenticated peer whose destination answers no dial is closed, and the
// endpoint keeps serving.
func TestInboundRefusesAnApplicationThatDoesNotAnswer(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	_, listeners := startTestEndpoint(t, volume, testPodAddress, unanswered(t))
	_, peerTLS := ca.meshConfigs(t)

	dialMeshPeer(t, listeners.inbound.Addr().String(), peerTLS)
	assertProbe(t, listeners, "/readyz", http.StatusOK)
}

// A connection the kernel holds no original destination for is refused rather
// than dialled.
func TestCapturedDestinationRefusesAnUntraceableConnection(t *testing.T) {
	endpoint := &podEndpoint{origDst: func(net.Conn) (string, error) { return "", errors.New("no conntrack entry") }}
	if _, err := endpoint.capturedDestination(nil); err == nil {
		t.Fatal("a connection without an original destination was accepted")
	}
}
