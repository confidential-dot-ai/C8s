//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// defaultTestProxyConfig returns a proxyConfig populated with the flag
// defaults, exactly as cobra would after parsing zero args.
func defaultTestProxyConfig(t *testing.T) *proxyConfig {
	t.Helper()
	var cfg proxyConfig
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	bindProxyFlags(fs, &cfg)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	return &cfg
}

// stubKubeClientset swaps the package-level clientset factory for the
// duration of the test.
func stubKubeClientset(t *testing.T, cs kubernetes.Interface, err error) {
	t.Helper()
	old := newKubeClientset
	newKubeClientset = func(string) (kubernetes.Interface, error) { return cs, err }
	t.Cleanup(func() { newKubeClientset = old })
}

// bindLoopback returns a held-open loopback listener for the code under test
// to adopt.
func bindLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) // ignored error once the server adopts ln
	return ln
}

func listenerPort(ln net.Listener) int {
	return ln.Addr().(*net.TCPAddr).Port
}

// bindProxyPorts hands runProxy pre-bound listeners and points the matching
// port fields at them.
func bindProxyPorts(t *testing.T, cfg *proxyConfig) {
	t.Helper()
	cfg.listeners.outbound = bindLoopback(t)
	cfg.listeners.inbound = bindLoopback(t)
	cfg.listeners.health = bindLoopback(t)
	cfg.outboundPort = listenerPort(cfg.listeners.outbound)
	cfg.inboundPort = listenerPort(cfg.listeners.inbound)
	cfg.healthPort = listenerPort(cfg.listeners.health)
}

// writeSelfSignedCertPEM writes a throwaway self-signed certificate to a
// temp file and returns its path (for --ca-cert loading).
func writeSelfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testPod(name, ns, podIP, hostIP string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		Name: name, Namespace: ns, UID: types.UID("uid-" + name), Labels: labels,
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  podIP,
			HostIP: hostIP,
		},
	}
}

func TestRunProxyConfigErrors(t *testing.T) {
	t.Setenv("NODE_IP", "")
	fakeCS := k8sfake.NewSimpleClientset()
	stubKubeClientset(t, fakeCS, nil)

	valid48 := strings.Repeat("ab", 48)
	tests := []struct {
		name    string
		mutate  func(*proxyConfig)
		wantErr string
	}{
		{"bad log level", func(c *proxyConfig) { c.logLevel = "bogus" }, "--log-level"},
		{"missing node IP", func(c *proxyConfig) {}, "node IP required"},
		{"invalid node IP", func(c *proxyConfig) { c.nodeIP = "not-an-ip" }, "must be a valid IP address"},
		{"invalid configuration", func(c *proxyConfig) { c.nodeIP = "127.0.0.1" }, "invalid configuration"},
		{"invalid measurement hex", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.measurements = "zz"
		}, "invalid measurement hex"},
		{"invalid measurement length", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.measurements = "abcd"
		}, "invalid measurement length"},
		{"blank measurement entry", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.measurements = valid48 + ","
		}, "invalid measurement length"},
		{"missing CA cert file", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.caCertPath = "/nonexistent/ca.pem"
		}, "load CA certificate"},
		{"invalid cert mode", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.certMode = "bogus"
		}, "invalid --cert-mode"},
		{"cds mode requires urls", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.certMode = "cds"
		}, "--cds-url and --attestation-api-url are required"},
		{"unsupported platform", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.platform = "frobnitz"
		}, "unsupported --platform"},
		{"empty platform", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.platform = ""
		}, "--platform is required"},
		{"invalid cds measurements", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.platform = "sev-snp"
			c.cdsMeasurements = "zz"
		}, "--cds-measurements"},
		{"valid cds measurements but bad mesh policy", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.measurements = valid48 + ",zz"
		}, "invalid measurement hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultTestProxyConfig(t)
			// A case that slips past validation binds ephemeral ports, not the fixed defaults.
			bindProxyPorts(t, cfg)
			cfg.logLevel = "error"
			cfg.localCIDRBootTimeout = time.Millisecond
			tt.mutate(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := runProxy(ctx, cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runProxy() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunProxyClientsetError(t *testing.T) {
	t.Setenv("NODE_IP", "10.0.0.9")
	stubKubeClientset(t, nil, fmt.Errorf("k8s in-cluster config: nope"))
	cfg := defaultTestProxyConfig(t)
	cfg.logLevel = "error"
	cfg.attestationApiURL = "http://127.0.0.1:1"
	err := runProxy(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "in-cluster config") {
		t.Fatalf("runProxy() error = %v, want in-cluster config error", err)
	}
}

// The default clientset factory must fail cleanly when not running in a
// cluster instead of proceeding with a nil rest config.
func TestNewKubeClientsetConfigOutcomes(t *testing.T) {
	orig := inClusterConfig
	t.Cleanup(func() { inClusterConfig = orig })

	// Exec and auth providers are mutually exclusive, so clientset
	// construction itself fails.
	inClusterConfig = func() (*rest.Config, error) {
		return &rest.Config{
			Host:         "https://127.0.0.1:1",
			ExecProvider: &clientcmdapi.ExecConfig{Command: "true", APIVersion: "client.authentication.k8s.io/v1"},
			AuthProvider: &clientcmdapi.AuthProviderConfig{Name: "azure"},
		}, nil
	}
	if cs, err := newKubeClientset(""); err == nil || !strings.Contains(err.Error(), "k8s clientset") {
		t.Fatalf("newKubeClientset() = %v, %v, want wrapped clientset error", cs, err)
	}

	inClusterConfig = func() (*rest.Config, error) {
		return &rest.Config{Host: "https://127.0.0.1:1"}, nil
	}
	cs, err := newKubeClientset("")
	if err != nil || cs == nil {
		t.Fatalf("newKubeClientset() = %v, %v, want a clientset from a valid config", cs, err)
	}
}

func TestNewKubeClientsetDefaultOutsideCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	cs, err := newKubeClientset("")
	if err == nil || !strings.Contains(err.Error(), "k8s in-cluster config") {
		t.Fatalf("newKubeClientset() error = %v, want in-cluster config error", err)
	}
	if cs != nil {
		t.Fatalf("newKubeClientset() clientset = %v, want nil on error", cs)
	}
}

// A kubeconfig path must be honored without consulting the in-cluster config,
// and a bad path must fail rather than fall back to it.
func TestNewKubeClientsetKubeconfigPath(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:1
  name: c
contexts:
- context:
    cluster: c
    user: u
  name: ctx
current-context: ctx
users:
- name: u
  user: {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := newKubeClientset(path)
	if err != nil || cs == nil {
		t.Fatalf("newKubeClientset(%q) = %v, %v, want a clientset", path, cs, err)
	}

	missing := filepath.Join(t.TempDir(), "absent")
	cs, err = newKubeClientset(missing)
	if err == nil || !strings.Contains(err.Error(), "--kubeconfig") {
		t.Fatalf("newKubeClientset(%q) = %v, %v, want --kubeconfig error", missing, cs, err)
	}
}

// TestRunProxyFullLifecycle drives runProxy end to end with a fake
// clientset and local fake CDS / probe endpoints (the attestation-api
// URL is a dead port), then cancels the context and expects a clean
// shutdown.
func TestRunProxyFullLifecycle(t *testing.T) {
	nodeIP := "127.0.0.1"
	pod := testPod("web", "default", "10.244.0.7", nodeIP, nil)
	stubKubeClientset(t, k8sfake.NewSimpleClientset(pod), nil)
	t.Setenv("NODE_IP", "")

	// Fake CDS: everything 404s; the upgrade goroutine retries with backoff.
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer cds.Close()

	// Cert-pipeline probe: first request unhealthy, then healthy, to walk
	// both probe branches.
	var probeCalls atomic.Int64
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if probeCalls.Add(1) == 1 {
			http.Error(w, "warming up", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer probe.Close()

	metricsFile := filepath.Join(t.TempDir(), "iptables-metrics.json")
	if err := writeIptablesMetricsFile(metricsFile, iptablesMetricsSnapshot{
		JumpPositionViolations: 3,
		UpdatedAtUnixNano:      time.Now().UnixNano(),
	}); err != nil {
		t.Fatal(err)
	}

	cfg := defaultTestProxyConfig(t)
	cfg.logLevel = "error"
	cfg.platform = "sev-snp"
	cfg.nodeIP = nodeIP
	cfg.attestationApiURL = "http://127.0.0.1:1" // refused instantly; warm-up failure is non-fatal
	bindProxyPorts(t, cfg)
	cfg.certDNSSAN = "mesh.example"
	cfg.measurements = strings.Repeat("ab", 48)
	cfg.cdsMeasurements = strings.Repeat("cd", 48)
	cfg.caCertPath = writeSelfSignedCertPEM(t)
	cfg.certMode = "cds"
	cfg.cdsURL = cds.URL
	cfg.certPipelineProbeURL = probe.URL + "/readyz"
	cfg.certPipelineProbeInterval = 20 * time.Millisecond
	cfg.certPipelineProbeTimeout = time.Second
	cfg.caPollInterval = 20 * time.Millisecond
	cfg.cdsRetryBackoff = 20 * time.Millisecond
	cfg.cdsRetryMaxBackoff = 40 * time.Millisecond
	cfg.cdsOpTimeout = 500 * time.Millisecond
	cfg.rotationTimeout = 300 * time.Millisecond
	cfg.metricsUpdateInterval = 10 * time.Millisecond
	cfg.localCIDRBootTimeout = time.Millisecond
	cfg.iptablesMetricsFile = metricsFile
	cfg.maxConns = 8
	cfg.maxConnsPerSource = 4
	cfg.drainTimeout = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runProxy(ctx, cfg) }()

	healthURL := fmt.Sprintf("http://127.0.0.1:%d/live", cfg.healthPort)
	assertEventually(t, 10*time.Second, func() bool {
		resp, err := http.Get(healthURL)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "health server never came up")

	// --measurements is set: the pinning gauge must read 1.
	if v := scrapedValue(t, cfg.healthPort, "armtls_mesh_measurement_pinning", nil); v != 1 {
		t.Errorf("measurement_pinning = %v with --measurements configured, want 1", v)
	}

	// Let the metric ticker read the sidecar file at least once, then remove
	// it so the read-after-success warning path runs too.
	time.Sleep(50 * time.Millisecond)
	os.Remove(metricsFile)
	time.Sleep(80 * time.Millisecond)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runProxy() = %v, want nil on context cancel", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runProxy did not shut down after cancel")
	}
}
