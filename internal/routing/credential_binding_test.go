package routing

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func warmBoundBackend(t *testing.T) (*fixture, *testBackend, *fakeBindings) {
	t.Helper()
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	bindings := newFakeBindings(map[string]Binding{"bound": f.bound(t)})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})
	if w := f.getOn("bound"); w.Code != http.StatusOK {
		t.Fatalf("first request = %d %q", w.Code, w.Body.String())
	}
	connection := web.seen().remoteAddr
	if w := f.getOn("bound"); w.Code != http.StatusOK {
		t.Fatalf("second request = %d %q", w.Code, w.Body.String())
	}
	if got := web.seen().remoteAddr; got != connection {
		t.Fatalf("backend connection = %q, want reused %q", got, connection)
	}
	return f, web, bindings
}

func TestBoundRequestRefusesRenewalOnAWarmBackend(t *testing.T) {
	f, web, bindings := warmBoundBackend(t)
	original := f.routerLeaf
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	w := f.getOn("bound")
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("request after renewal = %d %q, want 503 router_digest_changed", w.Code, w.Body.String())
	}
	if bindings.refused["bound"] != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("binding refusal = %q, want router_digest_changed", bindings.refused["bound"])
	}
	f.renew(t, original)
	if w := f.getOn("bound"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("request on the refused binding after restoring its leaf = %d, want 503", w.Code)
	}
	if hits := web.hits.Load(); hits != 2 {
		t.Fatalf("backend requests = %d, want only the two warmup requests", hits)
	}
}

func TestBoundRequestAcceptsRenewalUnderTheSameDigest(t *testing.T) {
	f, web, _ := warmBoundBackend(t)
	connection := web.seen().remoteAddr
	f.renew(t, issueLeaf(t, f.mesh, "router"))
	if w := f.getOn("bound"); w.Code != http.StatusOK {
		t.Fatalf("request after renewal under the same digest = %d %q, want 200", w.Code, w.Body.String())
	}
	if got := web.seen().remoteAddr; got != connection {
		t.Fatalf("backend connection = %q, want reused %q", got, connection)
	}
}

func TestBoundRequestWaitsForReadableCredentialsOnAWarmBackend(t *testing.T) {
	f, web, bindings := warmBoundBackend(t)
	f.publish(t, "garbage")
	if w := f.getOn("bound"); w.Code != http.StatusBadGateway {
		t.Fatalf("request with unreadable credentials = %d %q, want 502", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 2 {
		t.Fatalf("backend requests = %d, want only the two warmup requests", hits)
	}
	if len(bindings.refused) != 0 {
		t.Fatalf("binding refusals = %v, want none after a read failure", bindings.refused)
	}
	f.publish(t, caPEM(f.mesh))
	if w := f.getOn("bound"); w.Code != http.StatusOK {
		t.Fatalf("request after restoring credentials = %d %q, want 200", w.Code, w.Body.String())
	}
}

func TestBoundRequestRefusesADamagedStampOnAWarmBackend(t *testing.T) {
	f, web, _ := warmBoundBackend(t)
	f.renew(t, damagedStampLeaf(t))
	w := f.getOn("bound")
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("request with a damaged stamp = %d %q, want 503 router_digest_changed", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 2 {
		t.Fatalf("backend requests = %d, want only the two warmup requests", hits)
	}
}

func TestRouteChangePrecedesUnreadableRouterCredentials(t *testing.T) {
	f, web, _ := warmBoundBackend(t)
	f.apply(t, simpleManifest(2, web.addr()))
	f.publish(t, "garbage")
	w := f.getOn("bound")
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteDigestChanged {
		t.Fatalf("request with changed routes = %d %q, want 503 route_digest_changed", w.Code, w.Body.String())
	}
}

func TestTunnelRefusesRenewalOnAWarmBackend(t *testing.T) {
	f, web, bindings := warmBoundBackend(t)
	bound := bindings.entries["bound"]
	req := types.TunnelRequest{Path: "/", Headers: []types.HeaderField{{Name: "Host", Value: testHost}}}
	connection := web.seen().remoteAddr
	resp, err := f.proxy.Forward(outerRequest(testHost), req, bound)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("tunnel request = %d, %v, want 200", resp.Status, err)
	}
	if got := web.seen().remoteAddr; got != connection {
		t.Fatalf("tunnel backend connection = %q, want reused %q", got, connection)
	}
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	_, err = f.proxy.Forward(outerRequest(testHost), req, bound)
	var changed *BindingChangedError
	if !errors.As(err, &changed) || changed.Code != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("tunnel after renewal = %v, want router_digest_changed", err)
	}
	if hits := web.hits.Load(); hits != 3 {
		t.Fatalf("backend requests = %d, want only the three warmup requests", hits)
	}
}

func TestTunnelWaitsForReadableCredentialsOnAWarmBackend(t *testing.T) {
	f, web, bindings := warmBoundBackend(t)
	bound := bindings.entries["bound"]
	req := types.TunnelRequest{Path: "/", Headers: []types.HeaderField{{Name: "Host", Value: testHost}}}
	f.publish(t, "garbage")
	_, err := f.proxy.Forward(outerRequest(testHost), req, bound)
	var changed *BindingChangedError
	if err == nil || errors.As(err, &changed) {
		t.Fatalf("tunnel with unreadable credentials = %v, want a temporary failure", err)
	}
	if hits := web.hits.Load(); hits != 2 {
		t.Fatalf("backend requests = %d, want only the two warmup requests", hits)
	}
	f.publish(t, caPEM(f.mesh))
	resp, err := f.proxy.Forward(outerRequest(testHost), req, bound)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("tunnel after restoring credentials = %d, %v, want 200", resp.Status, err)
	}
}
