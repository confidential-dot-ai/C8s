package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// poll runs one poll of the last applied envelope, which records the router
// digest of the published router leaf (B10).
func (rs *routedServer) poll(t *testing.T) {
	t.Helper()
	poller := routing.NewPoller(routing.PollerConfig{
		State:      rs.state,
		Fetcher:    fixedEnvelope{rs.env},
		Keys:       fixedKeys(rs.keys),
		Transports: rs.transports,
	})
	if err := poller.Poll(t.Context()); err != nil {
		t.Fatalf("Poll() = %v, want nil", err)
	}
}

type fixedEnvelope struct{ env routes.Envelope }

func (f fixedEnvelope) Routes(context.Context) (routes.Envelope, error) { return f.env, nil }

type fixedKeys []*ecdsa.PublicKey

func (k fixedKeys) OperatorKeys(context.Context) ([]*ecdsa.PublicKey, error) { return k, nil }

// tunnelGet sends GET / to app.example through the session and returns the
// tunnel's HTTP status and error code, "" for a sealed answer.
func tunnelGet(t *testing.T, base, sessionID string, channel *overenc.Channel) (int, string) {
	t.Helper()
	resp := postSealedTunnel(t, base, channel, sessionID, types.TunnelRequest{
		Method: "GET", Path: "/", Headers: []types.HeaderField{{Name: "Host", Value: "app.example"}},
	})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, ""
	}
	var e types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("tunnel status %d with undecodable body: %v", resp.StatusCode, err)
	}
	return resp.StatusCode, e.Error
}

func TestE6TunnelRefusesAChangedBinding(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *routedServer)
		want   string
	}{
		{"E6 manifest applied", func(t *testing.T, rs *routedServer) { rs.apply(t, 2, time.Hour) }, types.ErrorCodeRouteDigestChanged},
		// The handshake bound the unstamped test leaf; the poll records the
		// stamped router leaf's digest.
		{"E6 router digest changed", func(t *testing.T, rs *routedServer) { rs.poll(t) }, types.ErrorCodeRouterDigestChanged},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRoutedServer(t)
			rs.apply(t, 1, time.Hour)
			channel, sessionID := establishSession(t, rs.ts.URL, make([]byte, 32))
			if status, code := tunnelGet(t, rs.ts.URL, sessionID, channel); status != http.StatusOK {
				t.Fatalf("tunnel before the change = %d %q, want 200", status, code)
			}
			<-rs.lastHost

			tc.change(t, rs)
			if status, code := tunnelGet(t, rs.ts.URL, sessionID, channel); status != http.StatusServiceUnavailable || code != tc.want {
				t.Fatalf("tunnel after the change = %d %q, want 503 %q", status, code, tc.want)
			}
			if status, code := tunnelGet(t, rs.ts.URL, sessionID, channel); status != http.StatusUnauthorized || code != types.ErrorCodeChannelError {
				t.Fatalf("tunnel after the refusal = %d %q, want 401 %q: the session ends", status, code, types.ErrorCodeChannelError)
			}
			if len(rs.lastHost) != 0 {
				t.Fatal("a refused request reached the backend")
			}
		})
	}
}

// attestLB runs attest-lb on connection, sending no connection header when
// connection is empty, and returns the response.
func attestLB(t *testing.T, base, connection string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/.well-known/c8s/attest-lb?nonce="+b64url(make([]byte, 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if connection != "" {
		req.Header.Set(routing.ConnectionHeader, connection)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// routedGet sends GET / for app.example to the routing listener on
// connection and returns the status and body.
func routedGet(t *testing.T, listener, connection string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, listener+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.example"
	if connection != "" {
		req.Header.Set(routing.ConnectionHeader, connection)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func TestE6ListenerRefusesABoundConnection(t *testing.T) {
	rs := newRoutedServer(t)
	listener := httptest.NewServer(rs.proxy)
	t.Cleanup(listener.Close)
	rs.apply(t, 1, time.Hour)
	if code := errorCode(t, attestLB(t, rs.ts.URL, "7.1")); code != "" {
		t.Fatalf("attest-lb = %q, want success", code)
	}
	if status, body := routedGet(t, listener.URL, "7.1"); status != http.StatusOK {
		t.Fatalf("GET on the bound connection = %d %q, want 200", status, body)
	}
	<-rs.lastHost

	rs.apply(t, 2, time.Hour)
	for range 2 { // the refusal does not unbind the connection
		if status, body := routedGet(t, listener.URL, "7.1"); status != http.StatusServiceUnavailable || body != types.ErrorCodeRouteDigestChanged {
			t.Fatalf("GET on the bound connection after another apply = %d %q, want 503 %q", status, body, types.ErrorCodeRouteDigestChanged)
		}
	}
	if len(rs.lastHost) != 0 {
		t.Fatal("a refused request reached the backend")
	}
	for _, connection := range []string{"7.2", ""} {
		if status, body := routedGet(t, listener.URL, connection); status != http.StatusOK {
			t.Fatalf("GET on unbound connection %q = %d %q, want 200", connection, status, body)
		}
		<-rs.lastHost
	}

	// A new handshake on the connection binds what it verified.
	if code := errorCode(t, attestLB(t, rs.ts.URL, "7.1")); code != "" {
		t.Fatalf("attest-lb again = %q, want success", code)
	}
	if status, body := routedGet(t, listener.URL, "7.1"); status != http.StatusOK {
		t.Fatalf("GET after attesting again = %d %q, want 200", status, body)
	}
}

func TestE5AttestLBBindsOnlyARelayedConnection(t *testing.T) {
	rs := newRoutedServer(t)
	rs.apply(t, 1, time.Hour)
	if code := errorCode(t, attestLB(t, rs.ts.URL, "")); code != "" {
		t.Fatalf("attest-lb without the relay header = %q, want success", code)
	}
	if n := len(rs.bindings.entries); n != 0 {
		t.Fatalf("attest-lb without the relay header left %d bindings, want 0", n)
	}
	resp := attestLB(t, rs.ts.URL, strings.Repeat("9", maxConnectionIDBytes+1))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attest-lb with an overlong connection identifier = %d, want 400", resp.StatusCode)
	}
}

func TestE7BindingCapRefusesHandshakes(t *testing.T) {
	rs := newRoutedServer(t)
	clock := &testClock{now: time.Now()}
	rs.bindings.max, rs.bindings.now = 1, clock.Now
	rs.apply(t, 1, time.Hour)
	for _, step := range []struct {
		connection, want string
	}{
		{"1.1", ""},
		{"1.2", types.ErrorCodeSessionsBusy},
		{"1.1", ""}, // rebinding takes no room
	} {
		if code := errorCode(t, attestLB(t, rs.ts.URL, step.connection)); code != step.want {
			t.Fatalf("attest-lb on %s = %q, want %q", step.connection, code, step.want)
		}
	}
	clock.Advance(lbBindingIdle + time.Second)
	if code := errorCode(t, attestLB(t, rs.ts.URL, "1.2")); code != "" {
		t.Fatalf("attest-lb once the binding expired = %q, want success", code)
	}
	if _, ok := rs.bindings.Lookup("1.1"); ok {
		t.Fatal("expired binding survived a handshake at the cap")
	}
}

func TestE7BindingIdleLifetime(t *testing.T) {
	clock := &testClock{now: time.Now()}
	b := NewBindings()
	b.now = clock.Now
	if err := b.bind("1.1", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	if err := b.bind("1.2", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(lbBindingIdle - time.Second)
	b.Touch("1.1")
	clock.Advance(2 * time.Second)
	b.prune()
	if _, ok := b.Lookup("1.1"); !ok {
		t.Fatal("touched binding expired, want it kept")
	}
	if _, ok := b.entries["1.2"]; ok {
		t.Fatal("idle binding survived prune")
	}
}
