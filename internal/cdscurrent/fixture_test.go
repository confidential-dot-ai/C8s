package cdscurrent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/casregister"
	"github.com/confidential-dot-ai/c8s/internal/cdscurrent"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	testCluster    = "acceptance-cluster"
	testHost       = "10.0.0.7"
	testSandbox    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigest     = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testSecretPath = "/secrets/pilot/operator"
)

type fixture struct {
	t           *testing.T
	directory   string
	configs     []casregister.Config
	authorities []*casregister.Acceptor
	proposers   []*casregister.Proposer
	replicas    []*cdscurrent.Replica
	policies    map[string]cdscurrent.Config
	operator    *ecdsa.PrivateKey
	signer      *operatorauth.Signer
}

func newFixture(
	t *testing.T,
	clusters ...string,
) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t:         t,
		directory: t.TempDir(),
		policies:  make(map[string]cdscurrent.Config),
		operator:  key,
		signer:    signer.WithTTL(operatorauth.MaxTokenValidity),
	}
	t.Cleanup(func() {
		f.loseCompute()
		for _, a := range f.authorities {
			_ = a.Close()
		}
	})
	for _, cluster := range clusters {
		wrappingKey := make(
			[]byte,
			32,
		)
		if _, err := rand.Read(wrappingKey); err != nil {
			t.Fatal(err)
		}
		f.policies[cluster] = cdscurrent.Config{
			ClusterID:           cluster,
			Key:                 wrappingKey,
			OperatorKeys:        []*ecdsa.PublicKey{&key.PublicKey},
			MaxPaths:            64,
			MaxPerHolder:        32,
			MaxSecretValueBytes: 4096,
			QueueSize:           16,
			ChallengeTTL:        time.Minute,
			LedgerTTL:           time.Hour,
		}
	}
	for i := range 3 {
		cfg := casregister.Config{
			Directory: filepath.Join(
				f.directory,
				fmt.Sprintf(
					"member-%d",
					i,
				),
			),
			MemberID: fmt.Sprintf(
				"member-%d",
				i,
			),
			Clusters:      clusters,
			QueueSize:     16,
			MaxValueBytes: 8 << 20,
		}
		a, err := casregister.Bootstrap(cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.configs = append(
			f.configs,
			cfg,
		)
		f.authorities = append(
			f.authorities,
			a,
		)
	}
	return f
}

func (f *fixture) peers() []casregister.Peer {
	peers := make(
		[]casregister.Peer,
		len(f.authorities),
	)
	for i, a := range f.authorities {
		peers[i] = a
	}
	return peers
}

func (f *fixture) replica(
	cluster string,
	peers []casregister.Peer,
) *cdscurrent.Replica {
	f.t.Helper()
	p, err := casregister.NewProposer(
		peers,
		cluster,
		16,
	)
	if err != nil {
		f.t.Fatal(err)
	}
	f.proposers = append(
		f.proposers,
		p,
	)
	r, err := cdscurrent.New(
		p,
		f.policies[cluster],
	)
	if err != nil {
		f.t.Fatal(err)
	}
	f.replicas = append(
		f.replicas,
		r,
	)
	return r
}

func (f *fixture) start(
	cluster string,
	enroll bool,
) []*cdscurrent.Replica {
	f.t.Helper()
	replicas := make(
		[]*cdscurrent.Replica,
		3,
	)
	for i := range replicas {
		replicas[i] = f.replica(
			cluster,
			f.peers(),
		)
	}
	if enroll {
		if err := replicas[0].Bootstrap(f.t.Context()); err != nil {
			f.t.Fatal(err)
		}
	}
	return replicas
}

func (f *fixture) loseCompute() {
	for _, r := range f.replicas {
		r.Close()
	}
	for _, p := range f.proposers {
		p.Close()
	}
	f.replicas, f.proposers = nil, nil
}

func (f *fixture) restartAuthorities() {
	f.t.Helper()
	for _, a := range f.authorities {
		if err := a.Close(); err != nil {
			f.t.Fatal(err)
		}
	}
	f.authorities = nil
	for _, cfg := range f.configs {
		a, err := casregister.Open(cfg)
		if err != nil {
			f.t.Fatal(err)
		}
		f.authorities = append(
			f.authorities,
			a,
		)
	}
}

func (f *fixture) authorization(
	path string,
	body []byte,
) string {
	f.t.Helper()
	auth, err := f.signer.Authorization(
		http.MethodPut,
		path,
		body,
	)
	if err != nil {
		f.t.Fatal(err)
	}
	return auth
}

func request(
	r *cdscurrent.Replica,
	method string,
	path string,
	body []byte,
	auth string,
	ifMatch string,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(
		method,
		path,
		bytes.NewReader(body),
	)
	if auth != "" {
		req.Header.Set(
			"Authorization",
			auth,
		)
	}
	if ifMatch != "" {
		req.Header.Set(
			"If-Match",
			ifMatch,
		)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(
		w,
		req,
	)
	return w
}

func requireStatus(
	t *testing.T,
	w *httptest.ResponseRecorder,
	want int,
) {
	t.Helper()
	if w.Code != want {
		t.Fatalf(
			"HTTP %d, want %d: %s",
			w.Code,
			want,
			w.Body.String(),
		)
	}
}

func policy(
	t *testing.T,
	marker string,
	grant bool,
) []byte {
	t.Helper()
	secrets := ""
	if grant {
		secrets = `,"secrets":{"policy":"allow","read":["/pilot/**"],"write":["/pilot/generated"]}`
	}
	raw := []byte(fmt.Sprintf(
		`{"schema":"c8s.allowlist/v1","workloads":{"%s":{"containers":[{"digest":"%s","command":{"policy":"exact","argv":["/pilot"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"}}]%s}}}`,
		marker,
		testDigest,
		secrets,
	))
	parsed, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := parsed.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

type inventory struct {
	signer *workloadclaims.SandboxTokenSigner
	calls  *atomic.Int64
}

func (i inventory) InventoryKey(
	_ context.Context,
	host string,
) (*ecdsa.PublicKey, error) {
	if i.calls != nil {
		i.calls.Add(1)
	}
	if host != testHost {
		return nil, fmt.Errorf(
			"unexpected inventory host %q",
			host,
		)
	}
	return i.signer.PublicKey(), nil
}

func (i inventory) FetchSandbox(
	_ context.Context,
	host string,
	sandbox string,
) (workloadclaims.SandboxDigestsResponse, error) {
	if i.calls != nil {
		i.calls.Add(1)
	}
	if host != testHost || sandbox != testSandbox {
		return workloadclaims.SandboxDigestsResponse{}, fmt.Errorf("unexpected inventory binding")
	}
	return workloadclaims.SandboxDigestsResponse{
		Digests: []string{testDigest},
		Containers: []workloadclaims.SandboxContainer{{
			Digest: testDigest,
			Argv:   []string{"/pilot"},
			Mounts: []pkgallowlist.ObservedMount{},
		}},
	}, nil
}

// This uses the real CA signing primitive and TLS verifier. It does not claim
// to exercise hardware attestation or the separate /attest admission route.
func tlsLeaf(
	t *testing.T,
	ca *issuer.CA,
	sandbox string,
) (tls.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{}
	if sandbox == "" {
		template.Subject = pkix.Name{CommonName: "localhost"}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificateRequest(
		rand.Reader,
		template,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, _, err := ca.SignCSR(issuer.SignCSRParams{
		CSR:       csr,
		TTL:       10 * time.Minute,
		SandboxID: sandbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		certPEM,
		pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyDER,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

type secretClient struct {
	server    *httptest.Server
	client    *http.Client
	inventory inventory
	key       *ecdsa.PrivateKey
}

func newSecretClient(
	t *testing.T,
	r *cdscurrent.Replica,
	ca *issuer.CA,
	leaf tls.Certificate,
	key *ecdsa.PrivateKey,
	inv inventory,
) *secretClient {
	t.Helper()
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, _ := tlsLeaf(
		t,
		ca,
		"",
	)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		req *http.Request,
	) {
		r.ServeSecret(
			w,
			req,
			inv,
			hosts,
		)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	server.StartTLS()
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{leaf},
	}}
	t.Cleanup(transport.CloseIdleConnections)
	t.Cleanup(server.Close)
	return &secretClient{
		server: server,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		inventory: inv,
		key:       key,
	}
}

func (c *secretClient) get(
	t *testing.T,
	nonce [32]byte,
) (int, []byte) {
	t.Helper()
	status, _, body := c.getResponse(
		t,
		nonce,
	)
	return status, body
}

func (c *secretClient) getResponse(
	t *testing.T,
	nonce [32]byte,
) (int, http.Header, []byte) {
	t.Helper()
	digest, err := workloadclaims.RequesterKeyDigest(&c.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	token, err := c.inventory.signer.Sign(
		testSandbox,
		digest,
		nonce[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		c.server.URL+testSecretPath,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(
		"Authorization",
		"SandboxToken "+base64.StdEncoding.EncodeToString(encoded),
	)
	req.Header.Set(
		"X-C8s-Challenge",
		base64.StdEncoding.EncodeToString(nonce[:]),
	)
	response, err := c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, body
}

func policyMarker(body []byte) (string, error) {
	var policy struct {
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	if err := json.Unmarshal(
		body,
		&policy,
	); err != nil {
		return "", err
	}
	if len(policy.Workloads) != 1 {
		return "", fmt.Errorf(
			"expected one workload, got %d",
			len(policy.Workloads),
		)
	}
	for marker := range policy.Workloads {
		return strings.Clone(marker), nil
	}
	panic("unreachable")
}
