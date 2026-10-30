package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// RenewingRouter stands in for a one-replica router front door whose get-cert
// renews the serving certificate: each renewal is a new key issued under the
// mesh CA, presented from the next handshake on, with a discovery document
// attesting it. Requests other than discovery go to the backend.
type RenewingRouter struct {
	*httptest.Server
	t testing.TB

	mu               sync.Mutex
	ca               meshCA
	serving          tls.Certificate              // presented from the next handshake on
	doc              []byte                       // served at /v1/discovery
	leafByClientAddr map[string]*x509.Certificate // set by each handshake, before any request on it
}

// RouterEvidence is the evidence a RenewingRouter's document carries: it names
// the serving cert it attests, so a verifier stub can tell renewals apart.
type RouterEvidence struct {
	ServingCertSHA256 string `json:"serving_cert_sha256"`
}

// NewRenewingRouter starts a RenewingRouter in front of the handler backend
// returns for it.
func NewRenewingRouter(t testing.TB, backend func(*RenewingRouter) http.Handler) *RenewingRouter {
	t.Helper()
	r := &RenewingRouter{t: t, ca: newMeshCA(t), leafByClientAddr: map[string]*x509.Certificate{}}
	r.Renew()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/discovery", r.serveDocument)
	mux.Handle("/", backend(r))
	r.Server = httptest.NewUnstartedServer(mux)
	// GetConfigForClient, not GetCertificate: an IP dial sends no server name,
	// and crypto/tls then skips GetCertificate.
	r.TLS = &tls.Config{GetConfigForClient: r.configForHandshake}
	r.StartTLS()
	t.Cleanup(r.Close)
	return r
}

// Renew issues a new key and leaf under the mesh CA and a document attesting it.
func (r *RenewingRouter) Renew() {
	r.RenewLeaf()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.doc = routerDocument(r.t, r.serving.Leaf)
}

// RenewLeaf issues a new key and leaf but keeps serving the previous document,
// as get-cert does between publishing a leaf and rewriting the document.
func (r *RenewingRouter) RenewLeaf() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.serving = r.ca.issue(r.t)
}

// RenewUnderNewCA renews under a new mesh CA key: what another deployment's
// router presents, or one whose CDS changed its CA key.
func (r *RenewingRouter) RenewUnderNewCA() {
	r.mu.Lock()
	r.ca = newMeshCA(r.t)
	r.mu.Unlock()
	r.Renew()
}

// Leaf returns the leaf the next handshake presents.
func (r *RenewingRouter) Leaf() *x509.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.serving.Leaf
}

// LeafOf returns the leaf presented on the connection req arrived on.
func (r *RenewingRouter) LeafOf(req *http.Request) *x509.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leafByClientAddr[req.RemoteAddr]
}

func (r *RenewingRouter) configForHandshake(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.leafByClientAddr[hello.Conn.RemoteAddr().String()] = r.serving.Leaf
	return &tls.Config{Certificates: []tls.Certificate{r.serving}}, nil
}

func (r *RenewingRouter) serveDocument(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	doc := r.doc
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(doc)
}

func routerDocument(t testing.TB, leaf *x509.Certificate) []byte {
	t.Helper()
	sum := sha256.Sum256(leaf.Raw)
	evidence, err := json.Marshal(RouterEvidence{ServingCertSHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(types.DiscoveryDocument{
		Version:   "1",
		PublicTLS: types.PublicTLSDiscovery{Mode: "cds"},
		CDSTLS: types.CDSTLSDiscovery{
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
		},
		Attestation: types.AttestationDiscovery{
			Challenge: base64.StdEncoding.EncodeToString([]byte("issuance-challenge")),
			Platform:  string(teetypes.PlatformAzSNP),
			Evidence:  evidence,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// meshCA issues router serving certs, as one CDS's mesh CA does.
type meshCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newMeshCA(t testing.TB) meshCA {
	t.Helper()
	key := newP256Key(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "c8s mesh CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return meshCA{cert: cert, key: key}
}

// issue returns a serving cert for a new key, its AuthorityKeyId naming ca.
func (ca meshCA) issue(t testing.TB) tls.Certificate {
	t.Helper()
	key := newP256Key(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "router"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newP256Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
