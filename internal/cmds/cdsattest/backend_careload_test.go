package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) serverCert(t *testing.T, name string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// After a CDS restart the mesh CA changes. The upstream hop must follow the
// CA file the fence reads, without a sidecar restart, and stop trusting the
// old CA.
func TestHTTPBackendReloadsUpstreamCA(t *testing.T) {
	const name = "upstream.test"
	oldCA, newCA := newTestCA(t, "old mesh CA"), newTestCA(t, "new mesh CA")
	oldLeaf, newLeaf := oldCA.serverCert(t, name), newCA.serverCert(t, name)
	var serving atomic.Pointer[tls.Certificate]
	serving.Store(oldLeaf)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstream.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serving.Load(), nil }}
	upstream.StartTLS()
	defer upstream.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeCA := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(caFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCA(oldCA.pem)
	backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{TrustedCAFile: caFile, ServerName: name})
	if err != nil {
		t.Fatal(err)
	}
	forward := func() error {
		backend.ResetConnections()
		_, err := backend.Forward(context.Background(), types.TunnelRequest{Method: http.MethodGet, Path: "/"})
		return err
	}

	if err := forward(); err != nil {
		t.Fatalf("old CA, old leaf: %v", err)
	}
	serving.Store(newLeaf)
	if err := forward(); err == nil {
		t.Fatal("a leaf from a CA outside the file was accepted")
	}
	writeCA(newCA.pem)
	if err := forward(); err != nil {
		t.Fatalf("new CA file, new leaf (no restart): %v", err)
	}
	serving.Store(oldLeaf)
	if err := forward(); err == nil {
		t.Fatal("the old CA is still trusted after the CA file changed")
	}

	other, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{TrustedCAFile: caFile, ServerName: "other.test"})
	if err != nil {
		t.Fatal(err)
	}
	serving.Store(newLeaf)
	if _, err := other.Forward(context.Background(), types.TunnelRequest{Method: http.MethodGet, Path: "/"}); err == nil {
		t.Fatal("a leaf for another name was accepted")
	}
}

// A new authority (CDS restarted with a new CA) drops the upstream pool like
// a bound change.
func TestRolloutAuthorityChangeResetsPool(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cds.setJournal("sha256:a", 1, "sha256:h1")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	var resets atomic.Int32
	fence.onBoundChange(func() { resets.Add(1) })
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := resets.Load()
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resets.Load() != base {
		t.Fatal("an unchanged state reset the pool")
	}
	ctx, cancel := fence.requestContext(context.Background())
	defer cancel()
	cds.setJournal("sha256:b", 0, "sha256:g0")
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resets.Load() != base+1 {
		t.Fatalf("resets after an authority change = %d, want %d", resets.Load(), base+1)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("an authority change did not cancel a forwarded request")
	}
	if !errors.Is(context.Cause(ctx), errAuthorityChanged) {
		t.Fatalf("cause = %v, want errAuthorityChanged", context.Cause(ctx))
	}
}
