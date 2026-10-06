//go:build linux

package armtlsmesh

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func TestHealthLive(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, 5*time.Second, 10*time.Second)
	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /live = %d, want 200", w.Code)
	}
}

func TestHealthReadyNotReady(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, 5*time.Second, 10*time.Second)
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /ready (not ready) = %d, want 503", w.Code)
	}
}

func TestHealthReadyAfterSignal(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, 5*time.Second, 10*time.Second)
	h.ready.Store(true)

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /ready (ready) = %d, want 200", w.Code)
	}
}

func TestHealthReadyAcceptLoopDegraded(t *testing.T) {
	m := testMetrics()
	h := newHealthServer(m, nil, nil, 10, 5*time.Second, 10*time.Second)
	h.ready.Store(true)

	// Below threshold: should be ready.
	m.acceptConsecutiveInbound.Store(h.acceptErrorThreshold - 1)
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("below threshold: GET /ready = %d, want 200", w.Code)
	}

	// At threshold (inbound): should degrade.
	m.acceptConsecutiveInbound.Store(h.acceptErrorThreshold)
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("at threshold (inbound): GET /ready = %d, want 503", w.Code)
	}

	// Reset inbound, trigger outbound.
	m.acceptConsecutiveInbound.Store(0)
	m.acceptConsecutiveOutbound.Store(h.acceptErrorThreshold)
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("at threshold (outbound): GET /ready = %d, want 503", w.Code)
	}

	// Recovery: reset both counters.
	m.acceptConsecutiveOutbound.Store(0)
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("after recovery: GET /ready = %d, want 200", w.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	m := testMetrics()
	m.connectionsTotal.WithLabelValues("inbound", "success").Add(42)
	m.bytesTotal.WithLabelValues("inbound", "forward").Add(1024)

	h := newHealthServer(m, nil, nil, 10, 5*time.Second, 10*time.Second)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	text := string(body)

	checks := []string{
		"armtls_mesh_active_connections",
		"armtls_mesh_connections_total",
		"armtls_mesh_bytes_total",
		"armtls_mesh_tls_dial_failures_total",
		"armtls_mesh_resolver_cache_entries",
		"armtls_mesh_route_errors_total",
		"armtls_mesh_dest_header_errors_total",
		"armtls_mesh_process_uptime_seconds",
		"go_goroutines",
		"go_memstats_heap_alloc_bytes",
		"go_memstats_heap_sys_bytes",
		"armtls_mesh_inbound_dest_rejected_total",
		"armtls_mesh_cert_rotation_failures_total",
		"armtls_mesh_resolver_last_event_timestamp_seconds",
		"armtls_mesh_cert_mode_configured",
		"armtls_mesh_cert_mode_mismatch",
		"armtls_mesh_accept_consecutive_errors",
		"armtls_mesh_connection_limit_per_source_rejected_total",
		"armtls_mesh_measurement_pinning",
		`direction="inbound",result="success"} 42`,
		`direction="inbound",side="forward"} 1024`,
		// Histogram metrics.
		"armtls_mesh_tls_handshake_duration_seconds_bucket",
		"armtls_mesh_tls_handshake_duration_seconds_sum",
		"armtls_mesh_tls_handshake_duration_seconds_count",
		"armtls_mesh_connection_duration_seconds_bucket",
		"armtls_mesh_connection_duration_seconds_sum",
		"armtls_mesh_connection_duration_seconds_count",
		"armtls_mesh_time_to_first_byte_seconds_bucket",
		"armtls_mesh_time_to_first_byte_seconds_sum",
		"armtls_mesh_time_to_first_byte_seconds_count",
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

// stubCertGate stands in for a armtls.CertManager so the readiness wiring can
// be exercised without minting short-lived certificates and sleeping past
// their expiry.
type stubCertGate struct{ ready, usable bool }

func (g stubCertGate) CertReady() bool  { return g.ready }
func (g stubCertGate) CertUsable() bool { return g.usable }

// CertReady is sticky ("provisioned at least once"), so it no longer implies
// "can serve TLS": once the manager refuses to hand an expired certificate to
// a handshake, a pod whose rotation has been failing past NotAfter fails
// every connection. /ready must take it out of the endpoint list instead of
// letting Kubernetes keep routing to it.
func TestHealthReadyGatesOnCertUsable(t *testing.T) {
	for _, tc := range []struct {
		name           string
		server, client certGate
		wantCode       int
		wantBody       string
	}{
		{"server cert provisioned but expired", stubCertGate{ready: true}, nil, http.StatusServiceUnavailable, "server cert outside its validity window"},
		{"client cert provisioned but expired", stubCertGate{ready: true, usable: true}, stubCertGate{ready: true}, http.StatusServiceUnavailable, "client cert outside its validity window"},
		{"both usable", stubCertGate{ready: true, usable: true}, stubCertGate{ready: true, usable: true}, http.StatusOK, "ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHealthServer(testMetrics(), nil, nil, 10, time.Second, time.Second)
			h.serverCertMgr = tc.server
			h.clientCertMgr = tc.client
			h.ready.Store(true)

			rec := httptest.NewRecorder()
			h.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("body = %q, want it to mention %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestHealthServerServe(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, time.Second, time.Second)
	h.ready.Store(true)
	ln := bindLoopback(t)
	port := listenerPort(ln)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- h.serve(ctx, ln.Addr().String(), ln) }()

	assertEventually(t, 5*time.Second, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/live", port))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "health serve never answered /live")

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve() = %v, want nil after shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop on cancel")
	}

	// A second serve on an already-bound port errors immediately.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := h.serve(context.Background(), held.Addr().String(), nil); err == nil {
		t.Fatal("serve on a bound port should error")
	}
}

func TestHealthReadyCertProvisioningGates(t *testing.T) {
	stub := mockapi.New(t)
	_, mgr, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: makeAttestFunc(attestclient.NewClient(""), stub.URL()),
		CertTTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name           string
		server, client *armtls.CertManager
	}{
		{"server cert not provisioned", mgr, nil},
		{"client cert not provisioned", nil, mgr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHealthServer(testMetrics(), tc.server, tc.client, 10, time.Second, time.Second)
			h.ready.Store(true)
			rec := httptest.NewRecorder()
			h.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if mgr.CertReady() {
				t.Skip("cert manager unexpectedly pre-provisioned")
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "not provisioned") {
				t.Errorf("body = %q", rec.Body.String())
			}
		})
	}
}
