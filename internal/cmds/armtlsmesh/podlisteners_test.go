//go:build linux

package armtlsmesh

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// A capture port already in use fails the bind, so the endpoint never runs on
// a partial set of listeners.
func TestBindRefusesAPortInUse(t *testing.T) {
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	inUse := taken.Addr().(*net.TCPAddr).Port
	endpoint := &podEndpoint{}

	listeners, err := endpoint.bind(context.Background(), 0, inUse, 0)
	if err == nil {
		listeners.close()
		t.Fatal("a capture port already in use was bound")
	}
	if listeners.outbound != nil || listeners.inbound != nil || listeners.probes != nil {
		t.Error("the failed bind returned a listener")
	}
}

// close closes every listener it holds, and holding none is closing none.
func TestPodListenersClose(t *testing.T) {
	podListeners{}.close()
	endpoint := &podEndpoint{}
	listeners, err := endpoint.bind(context.Background(), 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var bound []string
	for _, ln := range []net.Listener{listeners.outbound, listeners.inbound, listeners.probes} {
		bound = append(bound, net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)))
	}

	listeners.close()

	for _, addr := range bound {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			conn.Close()
			t.Errorf("%s still accepts connections", addr)
		}
	}
}
