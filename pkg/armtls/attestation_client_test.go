package armtls

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A proxy named in the environment must not see attestation-api requests.
func TestAttestationTransportIgnoresProxy(t *testing.T) {
	if directTransport().Proxy != nil {
		t.Fatal("attestation-api transport consults a proxy")
	}
}

// Each online verification builds a client; they must share one pool.
func TestAttestationClientsReuseConnections(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	for range 5 {
		if _, err := NewAttestationClient(srv.URL).Health(context.Background()); err != nil {
			t.Fatalf("Health: %v", err)
		}
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("5 clients opened %d connections, want 1", got)
	}
}
