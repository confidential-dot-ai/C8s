package routing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

const testHost = "app.example"

// bigBytes outgrows the loopback socket buffers, so the client's reading
// paces the writer.
const bigBytes = 24 << 20

var testReserved = []string{"/allowlist", "/.well-known/c8s/", "/healthz"}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newCA(t testing.TB, cn string) *issuer.CA {
	t.Helper()
	ca, err := issuer.NewCA(cn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// newIntermediate returns a CA that parent issued.
func newIntermediate(t testing.TB, parent *issuer.CA, cn string) *issuer.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := certutil.NewCATemplate(serial, cn, time.Now().Add(time.Hour))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, &key.PublicKey, parent.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issuer.CA{Cert: cert, Key: key}
}

func caPEM(cas ...*issuer.CA) string {
	var b bytes.Buffer
	for _, ca := range cas {
		b.Write(certutil.EncodeCertPEM(ca.Cert.Raw))
	}
	return b.String()
}

// testSandboxID is the workload instance a member leaf names.
const testSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

// issueLeaf mints a leaf the way CDS does, carrying the matched workload
// extension when workload is non-empty.
func issueLeaf(t testing.TB, ca *issuer.CA, workload string, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	params := issuer.SignCSRParams{CSR: csr, TTL: 30 * time.Minute, SandboxID: testSandboxID}
	if workload != "" {
		params.MatchedWorkload = &armtls.MatchedWorkload{
			Name:             workload,
			AllowlistVersion: "1",
			AllowlistDigest:  bytes.Repeat([]byte{0x42}, 32),
		}
	}
	certPEM, _, _, err := ca.SignCSR(params)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func writeFile(t testing.TB, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// seen is what a test backend observed about one request.
type seen struct {
	requestURI string
	host       string
	clientCert *x509.Certificate
	forwarded  string
	header     http.Header
	remoteAddr string
}

// testBackend is a backend serving leaf on the mesh profile, answering with
// its name.
type testBackend struct {
	name string
	ts   *httptest.Server
	hits atomic.Int64
	// slow, when set, holds requests to /slow: each sends on entered and
	// waits for release.
	entered, release chan struct{}
	// bigDone receives the outcome of each /big response, bigBytes long, and
	// the error that ends each /endless one.
	bigDone chan error
	mu      sync.Mutex
	last    seen
}

// startBackend starts a backend; each opt edits its TLS config first.
func startBackend(t testing.TB, name string, leaf tls.Certificate, opts ...func(*tls.Config)) *testBackend {
	t.Helper()
	b := &testBackend{name: name, entered: make(chan struct{}), release: make(chan struct{}), bigDone: make(chan error, 4)}
	b.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		s := seen{requestURI: r.RequestURI, host: r.Host, forwarded: r.Header.Get("X-Forwarded-For"), header: r.Header.Clone(), remoteAddr: r.RemoteAddr}
		s.clientCert = peerCertificate(r)
		b.mu.Lock()
		b.last = s
		b.mu.Unlock()
		switch r.URL.Path {
		case "/big":
			_, err := w.Write(make([]byte, bigBytes))
			b.bigDone <- err
			return
		case "/echo":
			// An upgraded connection that echoes each line back.
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprint(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
			for brw.Flush() == nil {
				line, err := brw.ReadString('\n')
				if err != nil {
					return
				}
				brw.WriteString(line)
			}
			return
		case "/endless":
			chunk := make([]byte, 1<<20)
			for {
				if _, err := w.Write(chunk); err != nil {
					b.bigDone <- err
					return
				}
			}
		}
		if r.URL.Path == "/slow" && b.entered != nil {
			b.entered <- struct{}{}
			<-b.release
		}
		w.Header().Set("X-Backend", name)
		_, _ = w.Write([]byte(name))
	}))
	testutil.ServeMeshBackend(b.ts, leaf)
	for _, opt := range opts {
		opt(b.ts.TLS)
	}
	b.ts.StartTLS()
	t.Cleanup(b.ts.Close)
	return b
}

// webPKI is the profile an address backend serves instead: a leaf for its
// own name under its own CA, and no mesh protocol.
func webPKI(cfg *tls.Config) {
	cfg.MinVersion = tls.VersionTLS12
	cfg.NextProtos = []string{"http/1.1"}
}

func (b *testBackend) addr() string {
	return strings.TrimPrefix(b.ts.URL, "https://")
}

// peerCertificate is the leaf the client presented: the request's own on a
// web-PKI connection, and the mesh connection's otherwise.
func peerCertificate(r *http.Request) *x509.Certificate {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0]
	}
	return testutil.MeshPeer(r)
}

func (b *testBackend) seen() seen {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

// operator signs manifests the way `c8s routes put` does.
type operator struct {
	signer *operatorauth.Signer
	keys   []*ecdsa.PublicKey
}

func newOperator(t testing.TB) operator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return operator{signer: signer, keys: []*ecdsa.PublicKey{&key.PublicKey}}
}

func (o operator) sign(t testing.TB, manifest []byte) routes.Envelope {
	t.Helper()
	auth, err := o.signer.Authorization(http.MethodPut, routes.Path, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return routes.Envelope{Manifest: manifest, Token: strings.TrimPrefix(auth, "Bearer ")}
}

type route struct {
	path, match string
	backend     map[string]string
}

func workloadRoute(path, match, address, workload string) route {
	return route{path, match, map[string]string{"address": address, "workload": workload}}
}

func addressRoute(path, match, address, serverName, ca string) route {
	return route{path, match, map[string]string{"address": address, "serverName": serverName, "ca": ca}}
}

type manifestSpec struct {
	revision  uint64
	notBefore time.Time
	maxAge    time.Duration
	hosts     map[string][]route
}

func (m manifestSpec) bytes(t testing.TB) []byte {
	t.Helper()
	if m.maxAge == 0 {
		m.maxAge = time.Hour
	}
	if m.notBefore.IsZero() {
		m.notBefore = time.Unix(0, 0)
	}
	hosts := map[string]any{}
	for name, rs := range m.hosts {
		var list []any
		for _, r := range rs {
			list = append(list, map[string]any{"path": r.path, "match": r.match, "backend": r.backend})
		}
		hosts[name] = map[string]any{"routes": list}
	}
	b, err := json.Marshal(map[string]any{
		"schema":        routes.Schema,
		"revision":      m.revision,
		"notBefore":     m.notBefore.UTC().Format(time.RFC3339),
		"maxAgeSeconds": int64(m.maxAge / time.Second),
		"hosts":         hosts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixture is a router: a mesh CA, its own mesh leaf published on a credential
// volume, an operator, and the routing engine wired the way cds-attest wires
// it.
type fixture struct {
	mesh       *issuer.CA
	volume     string
	routerLeaf tls.Certificate
	identity   *MeshIdentity
	op         operator
	clock      *fakeClock
	state      *State
	transports *Transports
	proxy      *Proxy
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{
		mesh:   newCA(t, "mesh"),
		volume: t.TempDir(),
		op:     newOperator(t),
		clock:  &fakeClock{now: time.Now()},
	}
	f.routerLeaf = issueLeaf(t, f.mesh, "router")
	f.publish(t, caPEM(f.mesh))
	certFile, keyFile, caFile := volumePaths(f.volume)
	identity, err := NewMeshIdentity(certFile, keyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	f.identity = identity
	f.state = NewState(StateConfig{Reserved: testReserved, MeshCAs: identity.MeshCAs, Now: f.clock.Now})
	f.transports = NewTransports(TransportConfig{MeshIdentity: identity.Credential})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Timeout: 10 * time.Second})
	return f
}

// publish publishes a generation holding the router's leaf and bundle as its
// mesh CAs.
func (f *fixture) publish(t testing.TB, bundle string) {
	t.Helper()
	key, ok := f.routerLeaf.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("router leaf key is %T, want an ECDSA key", f.routerLeaf.PrivateKey)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	publishGeneration(t, f.volume, certutil.EncodeCertPEM(f.routerLeaf.Certificate[0]), keyPEM, []byte(bundle))
}

// volumePaths are the three reader paths of the credential volume in dir.
func volumePaths(dir string) (certFile, keyFile, caFile string) {
	return filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt")
}

// publishGeneration writes the next generation of the credential volume in dir
// and flips the pointer onto it, the way get-cert publishes: the stable reader
// paths are replaced beside the pointer.
func publishGeneration(t testing.TB, dir string, chainPEM, keyPEM, caPEM []byte) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "generations"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	name := filepath.Join("generations", strconv.Itoa(len(entries)+1))
	generation := filepath.Join(dir, name)
	if err := os.MkdirAll(generation, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, data := range map[string][]byte{"tls.crt": chainPEM, "tls.key": keyPEM, "ca.crt": caPEM} {
		if err := os.WriteFile(filepath.Join(generation, file), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pointer := filepath.Join(dir, "current")
	if err := os.Symlink(name, pointer+".next"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pointer+".next", pointer); err != nil {
		t.Fatal(err)
	}
}

// apply signs and accepts m, failing the test on any error.
func (f *fixture) apply(t testing.TB, m manifestSpec) {
	t.Helper()
	if _, err := f.state.Accept(f.op.sign(t, m.bytes(t)), f.op.keys); err != nil {
		t.Fatalf("Accept(revision %d) = %v, want nil", m.revision, err)
	}
}

// get sends a request with the raw request target through the routing
// listener's handler.
func (f *fixture) get(target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = testHost
	r = r.WithContext(context.Background())
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	return w
}
