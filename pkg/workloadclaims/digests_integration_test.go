package workloadclaims

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The callback is otherwise only ever driven through a fake at the CDS
// interface boundary, so nothing exercises the wire: the identity decode, the
// 404 to ErrSandboxUnknown mapping, the response caps, or that the client dials
// DigestsPort rather than anything the caller supplied. This drives a real
// ServeDigests over a real TLS listener with a real DigestsClient transport.
//
// TLS here is a plain self-signed pair, not armTLS: attestation needs an
// attestation-api, and what is under test is the protocol above the handshake.
// routableLocalIP is an address the client's own validation accepts — loopback
// is rejected by design, so the test binds where production would: a routable
// interface address.
func routableLocalIP(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || !n.IP.IsGlobalUnicast() {
			continue
		}
		return n.IP
	}
	t.Skip("no routable IPv4 interface address in this environment")
	return nil
}

func serveDigestsTLS(t *testing.T, resolver SandboxResolver, identity []byte) (*DigestsClient, string) {
	t.Helper()
	ip := routableLocalIP(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "inventory"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}

	// DigestsPort is privileged and unbindable in CI, so point the client at an
	// ephemeral one. Everything above the port — the routes, the decode, the
	// status mapping — is exactly what production runs.
	l, err := tls.Listen("tcp", net.JoinHostPort(ip.String(), "0"), &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	prev := dialPort
	dialPort, err = strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dialPort = prev })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeDigests(ctx, l, resolver, identity) }()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &DigestsClient{
		http: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		},
	}, ip.String()
}

func TestDigestsCallbackOverTLS(t *testing.T) {
	signer, err := NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{digests: map[string][]string{
		"sandbox-1": {digestA, digestB},
		"sandbox-2": nil,
	}}
	c, host := serveDigestsTLS(t, resolver, signer.PublicKeyDER())
	ctx := context.Background()

	// The key CDS verifies a token against is the one the inventory serves.
	pub, err := c.InventoryKey(ctx, host)
	if err != nil {
		t.Fatalf("InventoryKey: %v", err)
	}
	if !pub.Equal(signer.PublicKey()) {
		t.Fatal("identity route served a key that is not the signer's")
	}

	digests, err := c.Fetch(ctx, host, "sandbox-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(digests) != 2 || digests[0] != digestA || digests[1] != digestB {
		t.Fatalf("digests = %v", digests)
	}

	// A known sandbox with nothing recorded answers [], which CDS treats as
	// fail-closed rather than an empty pass.
	empty, err := c.Fetch(ctx, host, "sandbox-2")
	if err != nil {
		t.Fatalf("Fetch empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("digests = %v, want none", empty)
	}

	// An unknown sandbox is distinguishable from a transport failure.
	if _, err := c.Fetch(ctx, host, "nosuchsandbox"); err != ErrSandboxUnknown {
		t.Fatalf("err = %v, want ErrSandboxUnknown", err)
	}
}

// The client dials DigestsPort and nothing else: the port is not carried in the
// token, so a requester cannot steer the callback at a port of its choosing.
func TestDigestsClientIgnoresCallerSuppliedPort(t *testing.T) {
	signer, err := NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	c, host := serveDigestsTLS(t, &fakeResolver{digests: map[string][]string{"sandbox-1": {digestA}}}, signer.PublicKeyDER())

	// A host:port pair is not a host, and is refused before any dial.
	if _, err := c.Fetch(context.Background(), host+":1", "sandbox-1"); err == nil {
		t.Fatal("Fetch accepted a host:port and may have dialed a caller-chosen port")
	}
}

// StartDigestsEndpoint serves the node's NRI inventory, so its fail-soft
// behaviour is worth pinning: a certificate warm-up that fails must not stop
// the endpoint binding and serving. On node-CVM the alternative is fatal —
// containerd requires the plugin, so exiting takes container creation down
// node-wide for what is only a degraded callback.
func TestStartDigestsEndpointServesDespiteWarmUpFailure(t *testing.T) {
	ip := routableLocalIP(t)

	// An attest func that always fails, so warm-up cannot succeed.
	attest := func(context.Context, string) (string, error) {
		return "", errTestAttest
	}

	// Bind an unprivileged port for the duration.
	probe, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, err := net.SplitHostPort(probe.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()

	prev := listenPort
	listenPort = port
	t.Cleanup(func() { listenPort = prev })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	signer, err := NewSandboxTokenSigner(ip.String())
	if err != nil {
		t.Fatal(err)
	}
	err = StartDigestsEndpoint(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)),
		&fakeResolver{sandboxID: "sandbox-1"}, signer.PublicKeyDER(),
		"sev-snp", attest, "http://127.0.0.1:1", armtls.Pins{})
	if err != nil {
		t.Fatalf("StartDigestsEndpoint returned an error for a warm-up failure; it must degrade, not fail: %v", err)
	}

	// The listener is bound even though the certificate could not be
	// provisioned — a token naming this host never points at a dead port.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, derr := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), portStr), 200*time.Millisecond)
		if derr == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("digests endpoint never bound: %v", derr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

var errTestAttest = errTest("attestation unavailable")

type errTest string

func (e errTest) Error() string { return string(e) }

// outboundHost is the last-resort advertise-host inference. It is a routing
// lookup, not a reachability test, so it answers for an address nothing is
// listening on — and fails for one that cannot be parsed.
func TestOutboundHost(t *testing.T) {
	got, err := outboundHost(context.Background(), "192.0.2.1:9")
	if err != nil {
		t.Fatalf("outboundHost: %v", err)
	}
	if net.ParseIP(got) == nil {
		t.Fatalf("outboundHost returned %q, want an IP", got)
	}
	// A bare host gets the default port appended rather than erroring.
	if _, err := outboundHost(context.Background(), "192.0.2.1"); err != nil {
		t.Fatalf("bare host: %v", err)
	}
	if _, err := outboundHost(context.Background(), "not a host:::"); err == nil {
		t.Fatal("unparseable target accepted")
	}
}

// With no explicit host, ResolveAdvertiseHost falls back to the route lookup
// and still validates the result.
func TestResolveAdvertiseHostInfers(t *testing.T) {
	got, err := ResolveAdvertiseHost(context.Background(), "", "192.0.2.1:9")
	if err != nil {
		t.Fatalf("ResolveAdvertiseHost: %v", err)
	}
	if net.ParseIP(got) == nil {
		t.Fatalf("inferred host = %q, want an IP", got)
	}
}

// NewDigestsClient rejects the configuration it cannot work without, at
// construction rather than at the first issuance, and warms its own certificate
// so the first pod does not pay the attestation round trip inside its deadline.
func TestNewDigestsClientConstruction(t *testing.T) {
	attest := func(context.Context, string) (string, error) { return "", errTestAttest }
	ctx := context.Background()

	if _, err := NewDigestsClient(ctx, "sev-snp", attest, "", armtls.Pins{}, 0); err == nil {
		t.Fatal("built with no attestation-api URL")
	}
	if _, err := NewDigestsClient(ctx, "bogus-platform", attest, "http://127.0.0.1:1", armtls.Pins{}, 0); err == nil {
		t.Fatal("built with an unsupported TEE platform")
	}
	// A warm-up that cannot succeed is a construction failure here, unlike the
	// server side: CDS has no work to do until it can present a client cert.
	if _, err := NewDigestsClient(ctx, "sev-snp", attest, "http://127.0.0.1:1", armtls.Pins{}, 0); err == nil {
		t.Fatal("built despite an attestation failure during warm-up")
	}
}

// InventoryKey fails closed on every shape of bad answer rather than returning
// a key CDS would then verify a token against.
func TestInventoryKeyRejectsBadAnswers(t *testing.T) {
	ip := routableLocalIP(t)
	for _, tc := range []struct {
		name     string
		identity []byte
	}{
		{"not a PKIX key", []byte("nonsense")},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, host := serveDigestsTLS(t, &fakeResolver{sandboxID: "sandbox-1"}, tc.identity)
			if _, err := c.InventoryKey(context.Background(), host); err == nil {
				t.Fatal("accepted an identity that is not an ECDSA public key")
			}
		})
	}
	_ = ip
}

// A host the client will not dial is refused before any connection: the same
// bound applies to the identity fetch as to the digests fetch, since both are
// driven by a requester-supplied host.
func TestInventoryKeyRejectsForgedHost(t *testing.T) {
	c := &DigestsClient{}
	if _, err := c.InventoryKey(context.Background(), "169.254.169.254"); err == nil {
		t.Fatal("identity fetch dialed the metadata service")
	}
}

// An inventory that is unreachable, or answers with something other than the
// digests contract, must surface as an error — CDS refuses issuance on any of
// them rather than proceeding with an unverified sandbox.
func TestDigestsClientTransportAndProtocolFailures(t *testing.T) {
	ip := routableLocalIP(t)

	t.Run("unreachable inventory", func(t *testing.T) {
		// Bind then close, so the port is routable but refuses.
		l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		_, portStr, _ := net.SplitHostPort(l.Addr().String())
		port, _ := strconv.Atoi(portStr)
		l.Close()

		prev := dialPort
		dialPort = port
		t.Cleanup(func() { dialPort = prev })

		c := &DigestsClient{http: &http.Client{Timeout: time.Second}}
		if _, err := c.Fetch(context.Background(), ip.String(), "sandbox-1"); err == nil {
			t.Fatal("Fetch succeeded against a closed port")
		}
		if _, err := c.InventoryKey(context.Background(), ip.String()); err == nil {
			t.Fatal("InventoryKey succeeded against a closed port")
		}
	})

	t.Run("inventory returns an error status", func(t *testing.T) {
		resolver := &erroringResolver{}
		c, host := serveDigestsTLS(t, resolver, []byte("identity"))
		if _, err := c.Fetch(context.Background(), host, "sandbox-1"); err == nil {
			t.Fatal("Fetch accepted a 500 from the inventory")
		} else if errors.Is(err, ErrSandboxUnknown) {
			t.Fatal("a resolver error was reported as an unknown sandbox")
		}
	})
}

// erroringResolver fails every digests lookup, which the endpoint turns into a
// 500 — distinct from the 404 that means "no such sandbox".
type erroringResolver struct{}

func (erroringResolver) SandboxForPeer(Peer) (string, error) { return "", errTestAttest }
func (erroringResolver) DigestsForSandbox(string) ([]string, []SandboxContainer, bool, error) {
	return nil, nil, false, errTestAttest
}

// clientAgainst points a DigestsClient at an arbitrary TLS handler, so the
// client's own robustness can be driven independently of a real inventory.
func clientAgainst(t *testing.T, h http.Handler) (*DigestsClient, string) {
	t.Helper()
	ip := routableLocalIP(t)
	srv := httptest.NewUnstartedServer(h)
	l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = l
	srv.StartTLS()
	t.Cleanup(srv.Close)

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	prev := dialPort
	dialPort = port
	t.Cleanup(func() { dialPort = prev })

	client := srv.Client()
	client.Timeout = 5 * time.Second
	return &DigestsClient{http: client}, ip.String()
}

// A misbehaving or impersonating inventory must not be able to feed CDS
// something it treats as an answer: every malformed shape is an error, and an
// error means issuance is refused.
func TestDigestsClientRejectsMalformedAnswers(t *testing.T) {
	ctx := context.Background()

	t.Run("digests body is not JSON", func(t *testing.T) {
		c, host := clientAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		if _, err := c.Fetch(ctx, host, "sandbox-1"); err == nil {
			t.Fatal("accepted a non-JSON digests body")
		}
	})

	t.Run("identity body is not JSON", func(t *testing.T) {
		c, host := clientAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		if _, err := c.InventoryKey(ctx, host); err == nil {
			t.Fatal("accepted a non-JSON identity body")
		}
	})

	t.Run("identity route errors", func(t *testing.T) {
		c, host := clientAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		if _, err := c.InventoryKey(ctx, host); err == nil {
			t.Fatal("accepted a 500 from the identity route")
		}
	})

	t.Run("identity key is RSA, not ECDSA", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		c, host := clientAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(InventoryIdentity{PublicKey: der})
		}))
		if _, err := c.InventoryKey(ctx, host); err == nil {
			t.Fatal("accepted a non-ECDSA inventory key")
		}
	})
}

// A body larger than what arrives with the headers must still be readable
// after the request returns.
func TestFetchSandboxReadsALargeBody(t *testing.T) {
	c, host := clientAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SandboxDigestsResponse{
			Containers: []SandboxContainer{{Argv: []string{strings.Repeat("a", 64<<10)}}},
		})
	}))
	// httptest's certificate names example.com, not the routable address.
	c.http.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com"
	for range 20 {
		out, err := c.FetchSandbox(context.Background(), host, "sandbox-1")
		if err != nil {
			t.Fatalf("FetchSandbox: %v", err)
		}
		if len(out.Containers) != 1 {
			t.Fatalf("containers = %d, want 1", len(out.Containers))
		}
	}
}
