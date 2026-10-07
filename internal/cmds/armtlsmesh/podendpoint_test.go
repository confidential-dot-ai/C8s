//go:build linux

package armtlsmesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// testPodAddress stands in for the pod's own address. A real endpoint never
// holds a loopback address (see TestOwnPodAddressesExcludeLoopback); a test's
// delivery destination has to be reachable.
var testPodAddress = podAddresses{netip.MustParseAddr("127.0.0.1")}

// testPeerAddress is a pod address that is not the test's own, so a captured
// destination on loopback is remote to the endpoint under test.
var testPeerAddress = podAddresses{netip.MustParseAddr("10.42.0.7")}

// startTestEndpoint runs an endpoint on ephemeral ports whose captured
// destination is supplied by the test instead of by the kernel.
func startTestEndpoint(t *testing.T, volume credentialVolume, own podAddresses, captured string) (*podEndpoint, podListeners) {
	t.Helper()
	e := &podEndpoint{
		credentials: &credentials{
			volume: volume,
			logger: discardLogger(),
		},
		own:     own,
		origDst: func(net.Conn) (string, error) { return captured, nil },
		logger:  discardLogger(),
		bufPool: newBufPool(0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	listeners, err := e.bind(ctx, 0, 0, 0)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	e.credentials.reload(time.Now())
	stopped := make(chan error, 1)
	go func() { stopped <- e.serve(ctx, listeners) }()
	t.Cleanup(func() {
		cancel()
		if err := <-stopped; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return e, listeners
}

// echoServer answers every connection with the bytes it reads and counts the
// connections it was handed, so a test can assert that nothing was delivered.
type echoServer struct {
	ln        net.Listener
	delivered atomic.Int64
}

func startEchoServer(t *testing.T, cfg *tls.Config) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
	}
	s := &echoServer{ln: ln}
	go func() {
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				return
			}
			s.delivered.Add(1)
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return s
}

func (s *echoServer) addr() string {
	return s.ln.Addr().String()
}

// roundTrip writes a message to conn and reads the answer back.
func roundTrip(t *testing.T, conn net.Conn, message string) string {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("write: %v", err)
	}
	answer := make([]byte, len(message))
	if _, err := io.ReadFull(conn, answer); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(answer)
}

// assertClosedWithoutData asserts that the endpoint closed the connection
// without relaying application bytes. A refused connection may be reset rather
// than closed cleanly, and a refused handshake still answers with a TLS alert,
// so the assertion is that the message never comes back.
func assertClosedWithoutData(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := []byte("ping")
	_, _ = conn.Write(message)
	answer, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("connection was not closed: %v", err)
	}
	if bytes.Contains(answer, message) {
		t.Error("the refused connection relayed application bytes")
	}
}

// An authenticated mesh peer is delivered to the destination the connection
// was captured for.
func TestInboundDeliversAnAuthenticatedPeer(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	app := startEchoServer(t, nil)
	_, listeners := startTestEndpoint(t, volume, testPodAddress, app.addr())
	_, peerTLS := ca.meshConfigs(t)

	conn, err := tls.Dial("tcp", listeners.inbound.Addr().String(), peerTLS)
	if err != nil {
		t.Fatalf("mesh peer handshake: %v", err)
	}
	defer conn.Close()
	if got := roundTrip(t, conn, "ping"); got != "ping" {
		t.Fatalf("relayed %q, want %q", got, "ping")
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != armtls.MeshALPN {
		t.Fatalf("negotiated %q, want %q", got, armtls.MeshALPN)
	}
}

// Nothing reaches the application until the peer is authenticated: plaintext
// behind a fake ClientHello, a peer from another mesh CA and a peer whose leaf
// names no workload instance are all refused.
func TestInboundRefusesAnUnauthenticatedPeer(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	foreign := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))

	_, foreignTLS := foreign.meshConfigs(t)
	anonymous := newMeshCA(t, time.Hour)
	_, anonymousTLS := anonymous.meshConfigsWithoutInstanceID(t)

	tests := []struct {
		name string
		talk func(t *testing.T, addr string)
	}{
		{"fake ClientHello then plaintext", func(t *testing.T, addr string) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// A TLS record header followed by application bytes.
			if _, err := conn.Write([]byte("\x16\x03\x01\x00\x05hello GET / HTTP/1.1\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			assertClosedWithoutData(t, conn)
		}},
		{"peer from another mesh CA", func(t *testing.T, addr string) {
			dialMeshPeer(t, addr, foreignTLS)
		}},
		{"peer leaf without a workload instance ID", func(t *testing.T, addr string) {
			dialMeshPeer(t, addr, anonymousTLS)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := startEchoServer(t, nil)
			_, listeners := startTestEndpoint(t, volume, testPodAddress, app.addr())
			tc.talk(t, listeners.inbound.Addr().String())
			if delivered := app.delivered.Load(); delivered != 0 {
				t.Fatalf("%d connections reached the application", delivered)
			}
		})
	}
}

// meshConfigsWithoutInstanceID is a peer presenting a leaf this endpoint would
// never publish: validly signed, with no workload instance ID.
func (ca meshCA) meshConfigsWithoutInstanceID(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	set := ca.issue(t, leafSpec{omitInstanceID: true})
	cert, err := tls.X509KeyPair(set.chainPEM, set.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newPublishedCredentials(&cert)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &armtls.MeshConfig{
		CertProvider: provider,
		MeshCA:       ca.cert,
	}
	server, _, err = armtls.NewMeshServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, _, err = armtls.NewMeshClientTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

// dialMeshPeer completes what it can of the handshake and reports nothing: the
// assertion is that the application saw no connection.
func dialMeshPeer(t *testing.T, addr string, cfg *tls.Config) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	assertClosedWithoutData(t, conn)
}

// A captured application connection reaches its original destination over
// armTLS under the mesh ALPN.
func TestOutboundCarriesCapturedTrafficOverARMTLS(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	peerTLS, _ := ca.meshConfigs(t)
	peer := startEchoServer(t, peerTLS)
	_, listeners := startTestEndpoint(t, volume, testPeerAddress, peer.addr())

	app, err := net.Dial("tcp", listeners.outbound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if got := roundTrip(t, app, "ping"); got != "ping" {
		t.Fatalf("carried %q, want %q", got, "ping")
	}
}

// A plaintext peer on the original destination gets no application bytes: the
// handshake is what admits the connection.
func TestOutboundRefusesAPlaintextDestination(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	plaintext := startEchoServer(t, nil)
	_, listeners := startTestEndpoint(t, volume, testPeerAddress, plaintext.addr())

	app, err := net.Dial("tcp", listeners.outbound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	assertClosedWithoutData(t, app)
}

// Without a usable generation the endpoint carries nothing in either
// direction and reports unready.
func TestEndpointWithoutCredentialsRefusesEveryConnection(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	app := startEchoServer(t, nil)
	endpoint, listeners := startTestEndpoint(t, volume, testPodAddress, app.addr())

	for name, ln := range map[string]net.Listener{
		"outbound": listeners.outbound,
		"inbound":  listeners.inbound,
	} {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertClosedWithoutData(t, conn)
		conn.Close()
	}
	if delivered := app.delivered.Load(); delivered != 0 {
		t.Fatalf("%d connections reached the application", delivered)
	}
	assertProbe(t, listeners, "/startupz", http.StatusOK)
	assertProbe(t, listeners, "/readyz", http.StatusServiceUnavailable)

	publishSet(t, volume, ca.issue(t, leafSpec{}))
	endpoint.credentials.reload(time.Now())
	assertProbe(t, listeners, "/readyz", http.StatusOK)

	withdrawSet(t, volume)
	endpoint.credentials.reload(time.Now())
	assertProbe(t, listeners, "/readyz", http.StatusServiceUnavailable)
}

// Both probes report unavailable until the endpoint runs on its listeners.
func TestProbesReportUnavailableBeforeInitialization(t *testing.T) {
	endpoint := &podEndpoint{
		credentials: &credentials{
			logger: discardLogger(),
		},
		logger: discardLogger(),
	}
	for _, probe := range []http.HandlerFunc{endpoint.handleStartup, endpoint.handleReady} {
		recorder := httptest.NewRecorder()
		probe(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("probe answered %d before initialization, want %d", recorder.Code, http.StatusServiceUnavailable)
		}
	}
}

// assertProbe asserts a probe's status and that its body carries neither
// credential material nor a forwarding destination.
func assertProbe(t *testing.T, listeners podListeners, path string, want int) {
	t.Helper()
	resp, err := http.Get("http://" + listeners.probes.Addr().String() + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("GET %s = %d (%q), want %d", path, resp.StatusCode, body, want)
	}
	if len(body) > 64 || strings.Contains(string(body), "BEGIN") {
		t.Fatalf("GET %s answered %d bytes: %q", path, len(body), body)
	}
}

// Inbound bytes reach an application port on one of the pod's own addresses
// and nothing else.
func TestRequireDeliverable(t *testing.T) {
	endpoint := &podEndpoint{
		own: podAddresses{netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("fd00::7")},
	}
	tests := []struct {
		dst     string
		wantErr bool
	}{
		{"10.42.0.7:8080", false},
		{"[fd00::7]:8080", false},
		{"10.42.0.7:15001", true},
		{"10.42.0.7:15006", true},
		{"10.42.0.7:15021", true},
		{"127.0.0.1:8080", true},
		{"10.42.0.8:8080", true},
		{"[fd00::8]:8080", true},
	}
	for _, tc := range tests {
		err := endpoint.requireDeliverable(netip.MustParseAddrPort(tc.dst))
		if (err != nil) != tc.wantErr {
			t.Errorf("requireDeliverable(%q) = %v, wantErr %v", tc.dst, err, tc.wantErr)
		}
	}
}

// A captured connection leaves the pod and enters its peer on an application
// port.
func TestRequireMeshDestination(t *testing.T) {
	endpoint := &podEndpoint{
		own: podAddresses{netip.MustParseAddr("10.42.0.7")},
	}
	tests := []struct {
		dst     string
		wantErr bool
	}{
		{"10.42.0.9:8080", false},
		{"10.42.0.7:8080", true},
		{"10.42.0.9:15006", true},
		{"10.42.0.9:15021", true},
	}
	for _, tc := range tests {
		err := endpoint.requireMeshDestination(netip.MustParseAddrPort(tc.dst))
		if (err != nil) != tc.wantErr {
			t.Errorf("requireMeshDestination(%q) = %v, wantErr %v", tc.dst, err, tc.wantErr)
		}
	}
}

// An unparseable original destination is refused rather than dialled.
func TestCapturedDestinationRefusesAMalformedAddress(t *testing.T) {
	endpoint := &podEndpoint{origDst: func(net.Conn) (string, error) { return "10.42.0.7", nil }}
	if _, err := endpoint.capturedDestination(nil); err == nil {
		t.Fatal("an address without a port was accepted")
	}
}

// The addresses inbound traffic may be delivered to never include loopback.
func TestOwnPodAddressesExcludeLoopback(t *testing.T) {
	own, err := ownPodAddresses()
	if err != nil {
		t.Skipf("no pod address in this namespace: %v", err)
	}
	for _, addr := range own {
		if addr.IsLoopback() {
			t.Errorf("%s is a loopback address", addr)
		}
	}
}

// The three reader paths must name three different files in one directory, so
// one pointer covers the whole generation.
func TestCredentialVolumeFor(t *testing.T) {
	if _, err := credentialVolumeFor("/run/certs/tls.crt", "/run/keys/tls.key", "/run/certs/ca.crt"); err == nil {
		t.Error("paths in two directories were accepted")
	}
	if _, err := credentialVolumeFor("/run/certs/tls.crt", "/run/certs/tls.crt", "/run/certs/ca.crt"); err == nil {
		t.Error("two paths naming one file were accepted")
	}
	volume, err := credentialVolumeFor("/run/certs/tls.crt", "/run/certs/tls.key", "/run/certs/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	if volume.pointerPath() != "/run/certs/current" {
		t.Errorf("pointerPath = %q", volume.pointerPath())
	}
}
