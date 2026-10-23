package cdsattest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
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
		{"E6 router digest changed", func(t *testing.T, rs *routedServer) {
			publishLeaf(t, rs.meshDir, namedLeafUnder(t, rs.ca, "router", bytes.Repeat([]byte{0x43}, 32)), rs.ca)
			rs.poll(t)
		}, types.ErrorCodeRouterDigestChanged},
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
	if code := errorCode(t, attestLB(t, rs.ts.URL, "1.2")); code != types.ErrorCodeSessionsBusy {
		t.Fatalf("attest-lb while a lapsed binding holds its room = %q, want %q", code, types.ErrorCodeSessionsBusy)
	}
	clock.Advance(lbBindingLife)
	if code := errorCode(t, attestLB(t, rs.ts.URL, "1.2")); code != "" {
		t.Fatalf("attest-lb once the binding's connection is gone = %q, want success", code)
	}
	if _, ok := rs.bindings.entries["1.1"]; ok {
		t.Fatal("gone binding survived a handshake at the cap")
	}
}

// TestE7PerClientBindingCap: one client's attest-lb bindings are capped
// below the store's bound, and another client still binds.
func TestE7PerClientBindingCap(t *testing.T) {
	b := NewBindings()
	b.maxClient = 1
	if err := b.bind("1.1", "client:a", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	if err := b.bind("1.2", "client:a", routing.Binding{}); !errors.Is(err, errClientBindingsFull) {
		t.Fatalf("second binding for one client = %v, want %v", err, errClientBindingsFull)
	}
	if err := b.bind("1.1", "client:a", routing.Binding{}); err != nil {
		t.Fatalf("rebind at the client's share = %v, want nil", err)
	}
	if err := b.bind("1.3", "client:b", routing.Binding{}); err != nil {
		t.Fatalf("another client's binding = %v, want nil", err)
	}
	b.max = 2 // the store is full: 1.1 and 1.3
	if err := b.bind("1.1", "client:c", routing.Binding{}); err != nil {
		t.Fatalf("rebind under another client at the global bound = %v, want nil", err)
	}
	if err := b.bind("1.1", "client:b", routing.Binding{}); !errors.Is(err, errClientBindingsFull) {
		t.Fatalf("rebind under a client at its share = %v, want %v", err, errClientBindingsFull)
	}
	b.max = maxLBBindings
	b.mu.Lock()
	b.dropLocked("1.1", b.entries["1.1"])
	b.mu.Unlock()
	if err := b.bind("1.2", "client:a", routing.Binding{}); err != nil {
		t.Fatalf("binding after the client's other binding dropped = %v, want nil", err)
	}
}

// TestE6RefuseSkipsAReplacedBinding: a refusal recorded for a request that
// held an earlier binding does not mark the binding a later handshake on the
// same connection installed meanwhile.
func TestE6RefuseSkipsAReplacedBinding(t *testing.T) {
	b := NewBindings()
	first := routing.Binding{RouterDigest: "a"}
	second := routing.Binding{RouterDigest: "b"}
	if err := b.bind("1.1", "c", first); err != nil {
		t.Fatal(err)
	}
	_, _, held, release, ok := b.Hold("1.1")
	if !ok {
		t.Fatal("Hold() = false, want true")
	}
	if err := b.bind("1.1", "c", second); err != nil {
		t.Fatal(err)
	}
	b.Refuse("1.1", held, types.ErrorCodeRouterDigestChanged)
	release()
	if _, refused, _, _, _ := b.Hold("1.1"); refused != "" {
		t.Fatalf("replaced binding refused with %q, want the refusal dropped", refused)
	}
	_, _, current, release2, _ := b.Hold("1.1")
	release2()
	b.Refuse("1.1", current, types.ErrorCodeRouterDigestChanged)
	if _, refused, _, _, _ := b.Hold("1.1"); refused != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("current binding refused with %q, want %q", refused, types.ErrorCodeRouterDigestChanged)
	}
}

func TestE7BindingIdleLifetime(t *testing.T) {
	clock := &testClock{now: time.Now()}
	b := NewBindings()
	b.now = clock.Now
	if err := b.bind("1.1", "c", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	if err := b.bind("1.2", "c", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(lbBindingIdle - time.Second)
	_, _, _, release, ok := b.Hold("1.1")
	if !ok {
		t.Fatal("Hold() of a live binding = false, want true")
	}
	release()
	clock.Advance(2 * time.Second)
	b.prune()
	if _, ok := b.entries["1.1"]; !ok {
		t.Fatal("used binding expired, want it kept")
	}
	if e, ok := b.entries["1.2"]; !ok || e.refused != types.ErrorCodeBindingExpired || e.client != "" {
		t.Fatalf("idle binding after prune = %+v, %v, want it lapsed to %s and charged to no client", e, ok, types.ErrorCodeBindingExpired)
	}
	if n := b.perClient["c"]; n != 1 {
		t.Fatalf("client charge after a lapse = %d, want 1", n)
	}
	clock.Advance(lbBindingIdle + time.Second)
	if _, refused, _, release, ok := b.Hold("1.1"); !ok || refused != types.ErrorCodeBindingExpired {
		t.Fatalf("Hold() of an idle binding = %q, %v, want %q, true: a lapse fails closed", refused, ok, types.ErrorCodeBindingExpired)
	} else {
		release()
	}
	clock.Advance(lbBindingLife + time.Second)
	if _, _, _, _, ok := b.Hold("1.1"); ok {
		t.Fatal("Hold() past the connection's life = true, want the binding dropped")
	}
}

// TestE7BindingHeldByARequestInFlight: a request outlasting the idle lifetime
// keeps its connection bound, and its end restarts the lifetime.
func TestE7BindingHeldByARequestInFlight(t *testing.T) {
	clock := &testClock{now: time.Now()}
	b := NewBindings()
	b.now = clock.Now
	if err := b.bind("1.1", "c", routing.Binding{RouterDigest: "D"}); err != nil {
		t.Fatal(err)
	}
	_, _, _, release, ok := b.Hold("1.1")
	if !ok {
		t.Fatal("Hold() of a live binding = false, want true")
	}
	clock.Advance(3 * lbBindingIdle)
	b.prune()
	if err := b.bind("1.2", "c", routing.Binding{}); err != nil { // prunes on insert
		t.Fatal(err)
	}
	if bound, _, _, again, ok := b.Hold("1.1"); !ok || bound.RouterDigest != "D" {
		t.Fatalf("Hold() during a long request = %+v, %v, want the binding kept", bound, ok)
	} else {
		again()
	}
	release()
	clock.Advance(lbBindingIdle - time.Second)
	if _, _, _, again, ok := b.Hold("1.1"); !ok {
		t.Fatal("Hold() within the idle lifetime after the request ended = false, want true")
	} else {
		again()
	}
}

// TestE7InsertPrunesExpiredBindings: an insert drops expired bindings without
// waiting for the sweep or the cap.
func TestE7InsertPrunesExpiredBindings(t *testing.T) {
	clock := &testClock{now: time.Now()}
	b := NewBindings()
	b.now = clock.Now
	if err := b.bind("1.1", "c", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(lbBindingIdle + time.Second)
	if err := b.bind("1.2", "c", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	if e, ok := b.entries["1.1"]; !ok || e.refused != types.ErrorCodeBindingExpired {
		t.Fatalf("idle binding after an insert = %+v, %v, want it lapsed", e, ok)
	}
	clock.Advance(lbBindingLife)
	if err := b.bind("1.3", "c", routing.Binding{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.entries["1.1"]; ok {
		t.Fatal("gone binding survived an insert")
	}
}

// TestE5HandshakeWaitsForTheRouterDigest: a handshake whose mesh leaf is
// stamped under another digest than the router checks requests against is
// refused before any evidence, rather than admit a session every request of
// which is refused.
func TestE5HandshakeWaitsForTheRouterDigest(t *testing.T) {
	rs := newRoutedServer(t, func(_ *routing.ProxyConfig, cfg *Config) {
		unstamped := writeTestMeshIdentity(t)
		cfg.MeshIdentityCertFile, cfg.MeshIdentityKeyFile, cfg.MeshIdentityCAFile = unstamped.certFile, unstamped.keyFile, unstamped.caFile
	})
	rs.apply(t, 1, time.Hour)
	rs.poll(t)
	if pq, lb := rs.handshakeCodes(t); pq != types.ErrorCodeBindingUnavailable || lb != types.ErrorCodeBindingUnavailable {
		t.Fatalf("handshakes with a leaf the router does not hold = %q, %q, want %q", pq, lb, types.ErrorCodeBindingUnavailable)
	}
}

// TestE5HandshakeWaitsForARenewalToReachTheRouter: a leaf stamped under
// another digest than the router's own credential is refused, and admitted
// once the router holds it.
func TestE5HandshakeWaitsForARenewalToReachTheRouter(t *testing.T) {
	var renewed tls.Certificate
	var renewedCA *issuer.CA
	rs := newRoutedServer(t, func(_ *routing.ProxyConfig, cfg *Config) {
		var err error
		if renewedCA, err = issuer.NewCA("mesh", time.Hour); err != nil {
			t.Fatal(err)
		}
		renewed = namedLeafUnder(t, renewedCA, "router", bytes.Repeat([]byte{0x43}, 32))
		_, dir := publishedMeshIdentity(t, renewed, renewedCA)
		cfg.MeshIdentityCertFile, cfg.MeshIdentityKeyFile, cfg.MeshIdentityCAFile = volumeFile(dir, "tls.crt"), volumeFile(dir, "tls.key"), volumeFile(dir, "ca.crt")
	})
	rs.apply(t, 1, time.Hour)
	rs.poll(t)
	if pq, lb := rs.handshakeCodes(t); pq != types.ErrorCodeBindingUnavailable || lb != types.ErrorCodeBindingUnavailable {
		t.Fatalf("handshakes with a leaf stamped under another digest = %q, %q, want %q", pq, lb, types.ErrorCodeBindingUnavailable)
	}
	publishLeaf(t, rs.meshDir, renewed, renewedCA)
	if pq, lb := rs.handshakeCodes(t); pq != "" || lb != "" {
		t.Fatalf("handshakes once the router holds the leaf = %q, %q, want success", pq, lb)
	}
}

// TestE6RefusalOutlivesItsCause: a connection refused once stays refused when
// the router digest changes back, until a handshake on it binds again.
func TestE6RefusalOutlivesItsCause(t *testing.T) {
	rs := newRoutedServer(t)
	listener := httptest.NewServer(rs.proxy)
	t.Cleanup(listener.Close)
	rs.apply(t, 1, time.Hour)
	if code := errorCode(t, attestLB(t, rs.ts.URL, "3.1")); code != "" {
		t.Fatalf("attest-lb = %q, want success", code)
	}
	original := namedLeaf(t, rs.ca, "router")
	publishLeaf(t, rs.meshDir, namedLeafUnder(t, rs.ca, "router", bytes.Repeat([]byte{0x43}, 32)), rs.ca)
	rs.poll(t)
	if status, body := routedGet(t, listener.URL, "3.1"); status != http.StatusServiceUnavailable || body != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("GET after the router renewed = %d %q, want 503 %q", status, body, types.ErrorCodeRouterDigestChanged)
	}
	publishLeaf(t, rs.meshDir, original, rs.ca)
	rs.poll(t)
	if status, body := routedGet(t, listener.URL, "3.1"); status != http.StatusServiceUnavailable || body != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("GET after the router digest changed back = %d %q, want 503 %q", status, body, types.ErrorCodeRouterDigestChanged)
	}
	if len(rs.lastHost) != 0 {
		t.Fatal("a refused request reached the backend")
	}
	if code := errorCode(t, attestLB(t, rs.ts.URL, "3.1")); code != "" {
		t.Fatalf("attest-lb again = %q, want success", code)
	}
	if status, body := routedGet(t, listener.URL, "3.1"); status != http.StatusOK {
		t.Fatalf("GET after attesting again = %d %q, want 200", status, body)
	}
}

// TestB10HandshakeRetiresPoolsOfARenewedLeaf: a handshake presenting a leaf
// renewed under another digest retires the connections pooled under the old
// one first, without waiting for a poll.
func TestB10HandshakeRetiresPoolsOfARenewedLeaf(t *testing.T) {
	rs := newRoutedServer(t)
	listener := httptest.NewServer(rs.proxy)
	t.Cleanup(listener.Close)
	rs.apply(t, 1, time.Hour)
	rs.poll(t)
	if status, body := routedGet(t, listener.URL, ""); status != http.StatusOK {
		t.Fatalf("GET = %d %q, want 200", status, body)
	}
	<-rs.lastHost

	// The backend stays stamped under the old digest: a fresh dial fails B8,
	// a pooled connection would not.
	publishLeaf(t, rs.meshDir, namedLeafUnder(t, rs.ca, "router", bytes.Repeat([]byte{0x43}, 32)), rs.ca)
	if code := errorCode(t, attestLB(t, rs.ts.URL, "")); code != "" {
		t.Fatalf("attest-lb with the renewed leaf = %q, want success", code)
	}
	if status, body := routedGet(t, listener.URL, ""); status != http.StatusBadGateway || !strings.Contains(body, "backend_digest_mismatch") {
		t.Fatalf("GET after the handshake = %d %q, want 502 backend_digest_mismatch: the old pool must be retired", status, body)
	}
}
