package acme

import (
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// freePort reserves a loopback port and releases it for the listener under
// test.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestRunIssuesAndInstalls drives the real run(): bootstrap placeholder, the
// challenge listener, ACME issuance against the fake directory, the installed
// key's mode, and shutdown on SIGTERM. nginx's own entrypoint reloads it.
func TestRunIssuesAndInstalls(t *testing.T) {
	ca := newTestCA(t)
	port := freePort(t)
	fake := newFakeACME(t, ca, "http://127.0.0.1:"+strconv.Itoa(port))

	// Stub nginx :80 server: proxies to the challenge listener run() starts,
	// so the front-door probe exercises the production topology.
	frontDoor := httptest.NewServer(httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "127.0.0.1:" + strconv.Itoa(port),
	}))
	t.Cleanup(frontDoor.Close)

	credentials := t.TempDir()
	certDir := filepath.Join(credentials, "tls")
	keyDir := filepath.Join(credentials, "key")
	cfg := config{
		domains:       []string{"lb.example.com", "infer.lb.example.com"},
		directoryURL:  fake.directoryURL(),
		email:         "ops@example.com",
		challengePort: port,
		httpPort:      serverPort(t, frontDoor.URL),
		certDir:       certDir,
		keyDir:        keyDir,
		logLevel:      "debug",
	}
	done := make(chan error, 1)
	go func() { done <- runWith(cfg, testPublicProbeClient(t, frontDoor.URL)) }()

	// The install lands a CA-issued (non-self-issued) leaf.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("no CA-issued certificate installed")
		}
		data, err := os.ReadFile(filepath.Join(certDir, certFile))
		if err == nil {
			leaf, err := certutil.ParseCertificatePEM(data)
			if err == nil && leaf.Issuer.CommonName == "Fake ACME CA" {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	info, err := os.Stat(filepath.Join(keyDir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	// Group-readable: nginx serves this key as another identity, and the
	// pod's fsGroup owns the directory.
	if info.Mode().Perm() != keyMode {
		t.Fatalf("key mode = %v, want %v", info.Mode().Perm(), os.FileMode(keyMode))
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop on SIGTERM")
	}
}

func TestRunValidatesConfig(t *testing.T) {
	cfg := validTestConfig()
	cfg.logLevel = "info"
	cfg.domains = []string{"-bad-"}
	if err := run(cfg); err == nil {
		t.Fatal("run accepted an invalid domain")
	}
}
