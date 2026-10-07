//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// stdoutCapture redirects os.Stdout into a drained pipe so tests can assert
// on the JSON logs runProxy emits through the default logger. Swap happens
// before the observed goroutine starts and restore after it is joined, so the
// os.Stdout variable is never accessed concurrently.
type stdoutCapture struct {
	buf  syncBuffer
	r, w *os.File
	old  *os.File
	done chan struct{}
}

func captureStdout(t *testing.T) *stdoutCapture {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	c := &stdoutCapture{r: r, w: w, old: os.Stdout, done: make(chan struct{})}
	os.Stdout = w
	go func() {
		defer close(c.done)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				c.buf.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(c.stop)
	return c
}

func (c *stdoutCapture) stop() {
	if os.Stdout == c.w {
		os.Stdout = c.old
	}
	c.w.Close()
	<-c.done
	c.r.Close()
}

func (c *stdoutCapture) String() string { return c.buf.String() }

func (c *stdoutCapture) hasMsg(msg string) bool {
	return hasMsg(decodeLogRecords(c.String()), msg)
}

// junkClientCert returns a self-signed cert with no armTLS extension: the
// mesh's peer verification must reject it.
func junkClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "junk"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func scrapedValue(t *testing.T, port int, name string, labels map[string]string) float64 {
	t.Helper()
	fams, err := tryScrapeMetrics(port)
	if err != nil {
		t.Fatalf("scrape /metrics: %v", err)
	}
	v, ok := familyValue(fams, name, labels)
	if !ok {
		t.Fatalf("metric %s%v not found", name, labels)
	}
	return v
}

func scrapedValueEventually(t *testing.T, port int, name string, labels map[string]string, cond func(float64) bool, msg string) {
	t.Helper()
	assertEventually(t, 10*time.Second, func() bool {
		fams, err := tryScrapeMetrics(port)
		if err != nil {
			return false
		}
		v, ok := familyValue(fams, name, labels)
		return ok && cond(v)
	}, msg)
}

// The invalid-measurement-length message must state the required hex length,
// which operators paste measurements against.
func TestRunProxyMeasurementLengthMessage(t *testing.T) {
	t.Setenv("NODE_IP", "")
	stubKubeClientset(t, k8sfake.NewSimpleClientset(), nil)
	cfg := defaultTestProxyConfig(t)
	bindProxyPorts(t, cfg)
	cfg.logLevel = "error"
	cfg.localCIDRBootTimeout = time.Millisecond
	cfg.nodeIP = "127.0.0.1"
	cfg.attestationApiURL = "http://127.0.0.1:1"
	cfg.measurements = "abcd"
	err := runProxy(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "96 hex characters") {
		t.Fatalf("err = %v, want the 96-hex-characters requirement in the message", err)
	}
}

// Self-signed mode with a working attestation endpoint: certificates warm up
// eagerly, readiness opens, expiry gauges are published for both roles, and
// the accept path enforces attestation and destination validation.
func TestRunProxySelfSignedReadiness(t *testing.T) {
	nodeIP := "127.0.0.1"
	stubKubeClientset(t, k8sfake.NewSimpleClientset(testPod("web", "default", "10.244.0.7", nodeIP, nil)), nil)
	t.Setenv("NODE_IP", "")
	attest := mockapi.New(t)

	cfg := defaultTestProxyConfig(t)
	cfg.logLevel = "error"
	cfg.platform = "sev-snp"
	cfg.nodeIP = nodeIP
	cfg.attestationApiURL = attest.URL()
	bindProxyPorts(t, cfg)
	cfg.rotationTimeout = 5 * time.Second
	cfg.metricsUpdateInterval = 10 * time.Millisecond
	cfg.localCIDRBootTimeout = time.Millisecond
	cfg.iptablesMetricsFile = ""
	cfg.drainTimeout = time.Second

	capture := captureStdout(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runProxy(ctx, cfg) }()
	joined := false
	join := func() {
		if joined {
			return
		}
		joined = true
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("runProxy = %v, want nil on cancel", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("runProxy did not shut down")
		}
	}
	defer join()

	// Eager warm-up must open readiness: /ready gates on both cert managers.
	assertEventually(t, 15*time.Second, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", cfg.healthPort))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "/ready never returned 200 after certificate warm-up")

	// Expiry gauges for both roles come from the metrics ticker.
	for _, role := range []string{"server", "client"} {
		scrapedValueEventually(t, cfg.healthPort, "armtls_mesh_cert_expiry_timestamp_seconds", map[string]string{"role": role},
			func(v float64) bool { return v > 0 }, "cert expiry gauge for "+role+" never set")
	}

	// No measurements configured: pinning gauge must be 0, and this proxy is
	// configured self-signed.
	if v := scrapedValue(t, cfg.healthPort, "armtls_mesh_measurement_pinning", nil); v != 0 {
		t.Errorf("measurement_pinning = %v without --measurements, want 0", v)
	}
	if v := scrapedValue(t, cfg.healthPort, "armtls_mesh_cert_mode_configured", map[string]string{"mode": "cds"}); v != 0 {
		t.Errorf("cert_mode_configured{cds} = %v in self-signed mode, want 0", v)
	}

	// A client without armTLS evidence must fail peer verification. The
	// dialer verifies the mesh server normally; its own junk cert is what
	// the server must reject.
	junkClientTLS, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{
		Policy:       &armtls.VerifyPolicy{AttestationApiURL: attest.URL()},
		CertProvider: staticCertProvider{junkClientCert(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.inboundPort), junkClientTLS)
	if err == nil {
		// TLS 1.3 may surface the rejection on first read instead of dial.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, rerr := conn.Read(make([]byte, 1)); rerr == nil {
			t.Error("handshake with junk client cert unexpectedly usable")
		}
		conn.Close()
	}
	scrapedValueEventually(t, cfg.healthPort, "armtls_mesh_attestation_failures_total", nil,
		func(v float64) bool { return v >= 1 }, "attestation failure never counted for a junk client cert")

	// A direct dial to the outbound listener has no SO_ORIGINAL_DST entry:
	// the route-error counter must move and the (unlimited) connection
	// semaphore must not reject anything.
	dconn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.outboundPort))
	if err != nil {
		t.Fatal(err)
	}
	dconn.Close()
	scrapedValueEventually(t, cfg.healthPort, "armtls_mesh_route_errors_total", nil,
		func(v float64) bool { return v >= 1 }, "route error never counted for a non-redirected dial")
	if v := scrapedValue(t, cfg.healthPort, "armtls_mesh_connection_limit_rejected_total", nil); v != 0 {
		t.Errorf("connection_limit_rejected = %v with --max-conns=0, want 0", v)
	}

	join()
	// After a clean join: warm-up succeeded and the health server exited
	// silently, so neither failure path may have logged.
	for _, msg := range []string{
		"server certificate warm-up failed",
		"client certificate warm-up failed",
		"health server error",
	} {
		if capture.hasMsg(msg) {
			t.Errorf("unexpected log %q; output: %s", msg, capture.String())
		}
	}
}

// CDS mode against a CDS that only 404s: the upgrade loop retries and warns,
// the CA refresh warns, the configured/active gauges disagree, and the cert
// pipeline probe tracks the probe target through healthy and unreachable.
func TestRunProxyCDSModeDegraded(t *testing.T) {
	nodeIP := "127.0.0.1"
	stubKubeClientset(t, k8sfake.NewSimpleClientset(), nil)
	t.Setenv("NODE_IP", "")

	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer cds.Close()

	var probeStatus atomic.Int64
	probeStatus.Store(http.StatusOK)
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(probeStatus.Load()))
	}))
	probeClosed := false
	defer func() {
		if !probeClosed {
			probe.Close()
		}
	}()

	cfg := defaultTestProxyConfig(t)
	cfg.logLevel = "info"
	cfg.platform = "sev-snp"
	cfg.nodeIP = nodeIP
	cfg.attestationApiURL = "http://127.0.0.1:1" // refused: warm-up failure is non-fatal
	bindProxyPorts(t, cfg)
	cfg.certMode = "cds"
	cfg.cdsURL = cds.URL
	cfg.cdsMeasurements = "" // deliberately unset: must warn
	cfg.certPipelineProbeURL = probe.URL + "/readyz"
	cfg.certPipelineProbeInterval = 20 * time.Millisecond
	cfg.certPipelineProbeTimeout = time.Second
	cfg.caPollInterval = 20 * time.Millisecond
	cfg.cdsRetryBackoff = 20 * time.Millisecond
	cfg.cdsRetryMaxBackoff = 40 * time.Millisecond
	cfg.cdsOpTimeout = 500 * time.Millisecond
	cfg.rotationTimeout = 200 * time.Millisecond
	cfg.metricsUpdateInterval = 10 * time.Millisecond
	cfg.localCIDRBootTimeout = time.Millisecond
	cfg.iptablesMetricsFile = ""
	cfg.drainTimeout = time.Second

	capture := captureStdout(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runProxy(ctx, cfg) }()
	joined := false
	join := func() {
		if joined {
			return
		}
		joined = true
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("runProxy = %v, want nil on cancel", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("runProxy did not shut down")
		}
	}
	defer join()

	assertEventually(t, 10*time.Second, func() bool {
		_, err := tryScrapeMetrics(cfg.healthPort)
		return err == nil
	}, "health server never came up")

	// Startup posture logs.
	assertEventually(t, 10*time.Second, func() bool {
		return capture.hasMsg("--cds-measurements not set; the armTLS handshake will accept any CDS measurement. Set this to the chart-distributed launch digest of CDS to close bootstrap MITM.") &&
			capture.hasMsg("CA bundle refresh enabled")
	}, "cds-mode startup logs missing")

	// Healthy probe: metric 1 and the transition logged exactly from the
	// initial unknown state.
	scrapedValueEventually(t, cfg.healthPort, "armtls_mesh_cert_pipeline_healthy", nil,
		func(v float64) bool { return v == 1 }, "cert pipeline probe never turned healthy")
	assertEventually(t, 10*time.Second, func() bool {
		return capture.hasMsg("cert pipeline probe healthy")
	}, "healthy probe transition never logged")

	// Probe target gone: connection refused must flip the gauge to 0 and log
	// the failure transition without crashing on the nil response.
	probe.Close()
	probeClosed = true
	scrapedValueEventually(t, cfg.healthPort, "armtls_mesh_cert_pipeline_healthy", nil,
		func(v float64) bool { return v == 0 }, "cert pipeline gauge never dropped after probe target closed")
	assertEventually(t, 10*time.Second, func() bool {
		return capture.hasMsg("cert pipeline probe failed")
	}, "failed probe transition never logged")

	// The upgrade goroutine must keep retrying against the 404 CDS, and the
	// CA refresh must warn on every failed poll.
	assertEventually(t, 10*time.Second, func() bool {
		return capture.hasMsg("cds certificate upgrade attempt failed (will retry)")
	}, "cds upgrade retry warning never logged")
	assertEventually(t, 10*time.Second, func() bool {
		return capture.hasMsg("cds CA bundle refresh failed")
	}, "CA refresh failure never logged")

	// Configured cds, still running self-signed: the mode gauges must expose
	// the stuck upgrade, and no upgrade success may have been claimed.
	if v := scrapedValue(t, cfg.healthPort, "armtls_mesh_cert_mode_configured", map[string]string{"mode": "cds"}); v != 1 {
		t.Errorf("cert_mode_configured{cds} = %v, want 1", v)
	}
	if v := scrapedValue(t, cfg.healthPort, "armtls_mesh_cert_mode", map[string]string{"mode": "cds"}); v != 0 {
		t.Errorf("cert_mode{cds} = %v while CDS 404s, want 0", v)
	}
	if v := scrapedValue(t, cfg.healthPort, "armtls_mesh_cert_mode_mismatch", nil); v != 1 {
		t.Errorf("cert_mode_mismatch = %v, want 1 (configured cds, active self-signed)", v)
	}
	if capture.hasMsg("certificate upgraded from self-signed to cds-issued (server)") {
		t.Error("upgrade success logged although CDS only 404s")
	}

	join()
	if capture.hasMsg("health server error") {
		t.Errorf("health server logged an error on clean shutdown: %s", capture.String())
	}
}
