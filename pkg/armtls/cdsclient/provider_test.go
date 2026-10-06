package cdsclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// mockServers creates test HTTP servers simulating CDS, the attestation
// service, and the in-process signer.
func mockServers(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, caBundle ...*x509.Certificate) (cdsSrv *httptest.Server, attestSvc *mockapi.Stub, issuer *httptest.Server) {
	t.Helper()
	return mockServersWithLeafValidity(t, caKey, caCert, time.Now(), time.Now().Add(1*time.Hour), caBundle...)
}

// mockServersWithLeafValidity is mockServers with a caller-chosen validity
// window on the issued leaf, for tests probing the client's window checks.
func mockServersWithLeafValidity(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafNotBefore, leafNotAfter time.Time, caBundle ...*x509.Certificate) (cdsSrv *httptest.Server, attestSvc *mockapi.Stub, issuer *httptest.Server) {
	t.Helper()
	if len(caBundle) == 0 {
		caBundle = []*x509.Certificate{caCert}
	}

	attestSvc = mockapi.New(t)

	// CDS: authenticate returns challenge, attest verifies and returns cert.
	// These tests cover the cdsclient HTTP plumbing in isolation; the
	// production ARmTLS handshake against CDS is exercised by
	// TestProviderARMTLSHandshakeRejectsWrongMeasurement etc. via a real
	// httptest.NewTLSServer wired with attested certs.
	cdsSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			challenge := make([]byte, 32)
			rand.Read(challenge)
			json.NewEncoder(w).Encode(types.ChallengeResponse{
				Challenge: base64.StdEncoding.EncodeToString(challenge),
			})

		case "/attest":
			var req types.AttestRequestBody
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			if req.CSR == "" {
				http.Error(w, "missing CSR", 400)
				return
			}

			// Parse the CSR and sign it with the CA.
			block, _ := pem.Decode([]byte(req.CSR))
			if block == nil {
				http.Error(w, "bad PEM", 400)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}

			serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      csr.Subject,
				NotBefore:    leafNotBefore,
				NotAfter:     leafNotAfter,
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				IPAddresses:  csr.IPAddresses,
				DNSNames:     csr.DNSNames,
			}
			copyARMTLSExtensionForTest(tmpl, csr)
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}

			w.Header().Set("Content-Type", "application/x-pem-file")
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
			for _, cert := range caBundle {
				pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			}

		default:
			http.NotFound(w, r)
		}
	}))

	// CA bundle endpoint: serves the CA certificate bundle.
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ca" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		for _, cert := range caBundle {
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		}
	}))

	return cdsSrv, attestSvc, issuer
}

func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func copyARMTLSExtensionForTest(tmpl *x509.Certificate, csr *x509.CertificateRequest) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(armtls.OIDARMTLSAttestation) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
				Id:    ext.Id,
				Value: ext.Value,
			})
			return
		}
	}
}

func testCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	return testCAWithValidity(t, "Test Mesh CA", time.Now(), time.Now().Add(365*24*time.Hour))
}

func testCAWithValidity(t *testing.T, commonName string, notBefore, notAfter time.Time) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func testCAWithParent(t *testing.T, parentKey *ecdsa.PrivateKey, parentCert *x509.Certificate, commonName string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func testCAForPublicKey(t *testing.T, parentKey *ecdsa.PrivateKey, parentCert *x509.Certificate, pub any, subject pkix.Name) *x509.Certificate {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func seedTrustedCABundle(t *testing.T, client *Client, certs ...*x509.Certificate) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	client.trustedCABundle = cloneCertSlice(certs)
}

func caBundleServer(t *testing.T, certs ...*x509.Certificate) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ca" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		for _, cert := range certs {
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		}
	}))
}

func TestProviderProvision(t *testing.T) {
	caKey, caCert := testCA(t)
	cdsSrv, attestSvc, issuer := mockServers(t, caKey, caCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cert, ttl, err := p.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if cert == nil {
		t.Fatal("cert is nil")
	}
	if cert.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if cert.Leaf == nil {
		t.Fatal("leaf cert is nil")
	}
	if len(cert.Certificate) < 2 {
		t.Fatalf("expected cert chain with leaf + CA, got %d certs", len(cert.Certificate))
	}
	if ttl <= 0 {
		t.Fatalf("TTL = %v, expected positive", ttl)
	}
	if !hasExtension(cert.Leaf, armtls.OIDARMTLSAttestation) {
		t.Fatal("issued cert is missing ARmTLS attestation extension")
	}

	// Verify the cert chains to the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("cert doesn't chain to CA: %v", err)
	}

	// Check subject.
	if cn := cert.Leaf.Subject.CommonName; cn != "armtls-mesh-10.0.0.1" {
		t.Errorf("CN = %q, want %q", cn, "armtls-mesh-10.0.0.1")
	}

	trusted := p.client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], caCert) {
		t.Fatalf("trusted CA bundle = %d cert(s), want only issued-cert CA", len(trusted))
	}
}

// TestProviderRefreshCABundleAfterProvision is the regression test for the
// in-guest refresh that could never succeed: Provision and RefreshCABundle
// must run over one client, or the continuity check has nothing to check
// against and every refresh fails closed.
func TestProviderRefreshCABundleAfterProvision(t *testing.T) {
	caKey, caCert := testCA(t)
	cdsSrv, attestSvc, issuer := mockServers(t, caKey, caCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}

	certs, err := p.RefreshCABundle(context.Background())
	if err != nil {
		t.Fatalf("refresh after provision: %v", err)
	}
	if len(certs) != 1 || !sameCertificate(certs[0], caCert) {
		t.Fatalf("refreshed bundle = %d cert(s), want the provisioning CA", len(certs))
	}
}

// TestProviderProvisionRejectsLeafOutsideValidityWindow proves an issued leaf
// the mesh could never serve — expired, or NotBefore beyond the shared
// clock-skew allowance — fails issuance instead of being cached.
func TestProviderProvisionRejectsLeafOutsideValidityWindow(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		// wantMsg pins WHICH check rejected the leaf. The expired case would
		// pass on the pre-existing "ttl <= 0" guard further down Provision
		// even with the validity check deleted, so asserting only "an error
		// happened" would not pin the window check at all.
		wantMsg string
	}{
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), "issued certificate: certificate expired at NotAfter"},
		{"not yet valid beyond skew", now.Add(certutil.LeafValiditySkew + time.Hour), now.Add(3 * time.Hour), "issued certificate: certificate is not yet valid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caKey, caCert := testCA(t)
			cdsSrv, attestSvc, issuer := mockServersWithLeafValidity(t, caKey, caCert, tc.notBefore, tc.notAfter)
			defer cdsSrv.Close()
			defer attestSvc.Close()
			defer issuer.Close()

			p, err := NewProvider(&Config{
				CDSURL:            cdsSrv.URL,
				AttestationApiURL: attestSvc.URL(),
				CDSCAURL:          issuer.URL,
				NodeIP:            "10.0.0.1",
				TEEType:           armtls.TEETypeSEVSNP,
				HTTPClient:        plainHTTPClient(),
				NodeName:          "test-node",
			}, nil)
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = p.Provision(context.Background())
			if err == nil {
				t.Fatal("issued certificate outside its validity window was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want the validity-window rejection (%q)", err, tc.wantMsg)
			}
		})
	}
}

func TestRefreshCABundle(t *testing.T) {
	_, caCert := testCA(t)

	issuer := caBundleServer(t, caCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, caCert)

	certs, err := client.refreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 CA cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "Test Mesh CA" {
		t.Errorf("CA CN = %q, want %q", certs[0].Subject.CommonName, "Test Mesh CA")
	}
}

func TestRefreshCABundleUsesExplicitCACertURL(t *testing.T) {
	_, caCert := testCA(t)
	var hitCustom atomic.Bool

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/ca.pem" {
			http.NotFound(w, r)
			return
		}
		hitCustom.Store(true)
		w.Header().Set("Content-Type", "application/x-pem-file")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	}))
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          "http://unused.invalid",
		CACertURL:         issuer.URL + "/custom/ca.pem",
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, caCert)

	certs, err := client.refreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hitCustom.Load() {
		t.Fatal("custom CA URL was not requested")
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 CA cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "Test Mesh CA" {
		t.Errorf("CA CN = %q, want %q", certs[0].Subject.CommonName, "Test Mesh CA")
	}
}

func TestRefreshCABundleRejectsUntrustedInitialBundle(t *testing.T) {
	_, caCert := testCA(t)

	issuer := caBundleServer(t, caCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})

	_, err := client.refreshCABundle(context.Background())
	if err == nil {
		t.Fatal("RefreshCABundle succeeded before certificate provisioning seeded trust")
	}
	if !strings.Contains(err.Error(), "requires a trusted CA") {
		t.Fatalf("RefreshCABundle error = %v, want trusted CA error", err)
	}
}

func TestRefreshCABundleDoesNotAddUnverifiedRotationRoot(t *testing.T) {
	_, oldCert := testCA(t)
	_, newCert := testCA(t)

	issuer := caBundleServer(t, newCert, oldCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, oldCert)

	certs, err := client.refreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || !sameCertificate(certs[0], oldCert) {
		t.Fatalf("RefreshCABundle returned %d cert(s), want only already trusted old CA", len(certs))
	}

	trusted := client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], oldCert) {
		t.Fatalf("trusted CA bundle added an unverified root, count=%d", len(trusted))
	}
}

func TestRefreshCABundleDoesNotTrustPublicKeyCloneChain(t *testing.T) {
	_, trustedCert := testCA(t)
	attackerKey, attackerRoot := testCA(t)
	cloneCert := testCAForPublicKey(t, attackerKey, attackerRoot, trustedCert.PublicKey, trustedCert.Subject)

	issuer := caBundleServer(t, cloneCert, attackerRoot, trustedCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, trustedCert)

	certs, err := client.refreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || !sameCertificate(certs[0], trustedCert) {
		t.Fatalf("RefreshCABundle returned %d cert(s), want only exact trusted CA", len(certs))
	}

	trusted := client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], trustedCert) {
		t.Fatalf("trusted CA bundle accepted public-key clone chain, count=%d", len(trusted))
	}
}

func TestRefreshCABundleRejectsTrustedSignerPublicKeyClone(t *testing.T) {
	trustedKey, trustedCert := testCA(t)
	cloneCert := testCAForPublicKey(t, trustedKey, trustedCert, trustedCert.PublicKey, trustedCert.Subject)

	issuer := caBundleServer(t, cloneCert, trustedCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, trustedCert)

	certs, err := client.refreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || !sameCertificate(certs[0], trustedCert) {
		t.Fatalf("RefreshCABundle returned %d cert(s), want only exact trusted CA", len(certs))
	}

	trusted := client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], trustedCert) {
		t.Fatalf("trusted CA bundle accepted same-key replacement CA, count=%d", len(trusted))
	}
}

func TestProviderProvisionRetainsRotationParentCA(t *testing.T) {
	oldKey, oldCert := testCA(t)
	newKey, newCert := testCAWithParent(t, oldKey, oldCert, "Rotated Mesh CA")
	cdsSrv, attestSvc, issuer := mockServers(t, newKey, newCert, newCert, oldCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}

	trusted := p.client.TrustedCABundle()
	if len(trusted) != 2 || !sameCertificate(trusted[0], newCert) || !sameCertificate(trusted[1], oldCert) {
		t.Fatalf("trusted CA bundle = %d cert(s), want rotated CA followed by parent CA", len(trusted))
	}
}

func TestProviderProvisionRetainsPreviouslyTrustedPublishedCA(t *testing.T) {
	_, oldCert := testCA(t)
	newKey, newCert := testCA(t)
	cdsSrv, attestSvc, issuer := mockServers(t, newKey, newCert, newCert, oldCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	})
	seedTrustedCABundle(t, client, oldCert)
	p, err := newProviderWithClient(client, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}

	trusted := p.client.TrustedCABundle()
	if len(trusted) != 2 || !sameCertificate(trusted[0], newCert) || !sameCertificate(trusted[1], oldCert) {
		t.Fatalf("trusted CA bundle = %d cert(s), want new CA followed by previously trusted old CA", len(trusted))
	}
}

func TestProviderProvisionDoesNotRetainUntrustedPublishedCA(t *testing.T) {
	_, oldCert := testCA(t)
	newKey, newCert := testCA(t)
	cdsSrv, attestSvc, issuer := mockServers(t, newKey, newCert, newCert, oldCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}

	trusted := p.client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], newCert) {
		t.Fatalf("trusted CA bundle = %d cert(s), want only newly verified CA", len(trusted))
	}
}

func TestProviderProvisionRetainsMultiGenerationRotationParents(t *testing.T) {
	rootKey, rootCert := testCA(t)
	intermediateKey, intermediateCert := testCAWithParent(t, rootKey, rootCert, "First Rotated Mesh CA")
	currentKey, currentCert := testCAWithParent(t, intermediateKey, intermediateCert, "Second Rotated Mesh CA")
	cdsSrv, attestSvc, issuer := mockServers(t, currentKey, currentCert, currentCert, intermediateCert, rootCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}

	trusted := p.client.TrustedCABundle()
	if len(trusted) != 3 ||
		!sameCertificate(trusted[0], currentCert) ||
		!sameCertificate(trusted[1], intermediateCert) ||
		!sameCertificate(trusted[2], rootCert) {
		t.Fatalf("trusted CA bundle = %d cert(s), want current, intermediate, root", len(trusted))
	}
}

func TestProviderProvisionRejectsBundleWhoseFirstCADoesNotSignLeaf(t *testing.T) {
	realKey, realCert := testCA(t)
	_, attackerRoot := testCA(t)
	cdsSrv, attestSvc, issuer := mockServers(t, realKey, realCert, attackerRoot, realCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err == nil {
		t.Fatal("Provision accepted a bundle whose first CA did not sign the issued leaf")
	}
}

func TestProviderProvisionRejectsLeafForDifferentKey(t *testing.T) {
	caKey, caCert := testCA(t)

	attestSvc := mockapi.New(t)

	cdsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			challenge := make([]byte, 32)
			rand.Read(challenge)
			json.NewEncoder(w).Encode(types.ChallengeResponse{
				Challenge: base64.StdEncoding.EncodeToString(challenge),
			})
		case "/attest":
			wrongKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      pkix.Name{CommonName: "wrong-key"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			}
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &wrongKey.PublicKey, caKey)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
		default:
			http.NotFound(w, r)
		}
	}))
	defer cdsSrv.Close()

	issuer := caBundleServer(t, caCert)
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err == nil {
		t.Fatal("Provision accepted a leaf certificate for a different private key")
	}
}

func TestProviderProvisionDoesNotTrustAppendedPublicKeyCloneChain(t *testing.T) {
	realKey, realCert := testCA(t)
	attackerKey, attackerRoot := testCA(t)
	alternateRealCA := testCAForPublicKey(t, attackerKey, attackerRoot, realCert.PublicKey, realCert.Subject)
	cdsSrv, attestSvc, issuer := mockServers(t, realKey, realCert, realCert, alternateRealCA, attackerRoot)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}

	trusted := p.client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], realCert) {
		t.Fatalf("trusted CA bundle accepted appended public-key clone chain, count=%d", len(trusted))
	}
}

func TestProviderProvisionDoesNotTrustUnauthenticatedAlternateCA(t *testing.T) {
	realKey, realCert := testCA(t)
	attackerKey, attackerRoot := testCA(t)
	alternateRealCA := testCAForPublicKey(t, attackerKey, attackerRoot, realCert.PublicKey, realCert.Subject)
	var publicCAHit atomic.Bool

	cdsSrv, attestSvc, issuer := mockServers(t, realKey, realCert, realCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()
	publicIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicCAHit.Store(true)
		w.Header().Set("Content-Type", "application/x-pem-file")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: alternateRealCA.Raw})
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: attackerRoot.Raw})
	}))
	defer publicIssuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          publicIssuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	if publicCAHit.Load() {
		t.Fatal("initial provisioning fetched unauthenticated public CA bundle")
	}
	trusted := p.client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], realCert) {
		t.Fatalf("trusted CA bundle = %d cert(s), want only authenticated real CA", len(trusted))
	}
}

func TestProviderProvisionHonorsCanceledContext(t *testing.T) {
	realKey, realCert := testCA(t)
	cdsSrv, attestSvc, issuer := mockServers(t, realKey, realCert, realCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := p.Provision(ctx); err == nil {
		t.Fatal("Provision succeeded with canceled context")
	} else if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("Provision error = %v, want context canceled", err)
	}
}

func TestRefreshCABundleAcceptsContinuitySignedRotationCA(t *testing.T) {
	oldKey, oldCert := testCA(t)
	_, newCert := testCAWithParent(t, oldKey, oldCert, "Rotated Mesh CA")

	issuer := caBundleServer(t, newCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, oldCert)

	certs, err := client.refreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || !sameCertificate(certs[0], newCert) {
		t.Fatalf("RefreshCABundle returned %d cert(s), want continuity-signed new CA", len(certs))
	}

	trusted := client.TrustedCABundle()
	if len(trusted) != 1 || !sameCertificate(trusted[0], newCert) {
		t.Fatalf("trusted CA bundle did not switch to continuity-signed new CA, count=%d", len(trusted))
	}
}

func TestRefreshCABundleAcceptsContinuitySignedRotationChainInBundleOrder(t *testing.T) {
	oldKey, oldCert := testCA(t)
	previousKey, previousCert := testCAWithParent(t, oldKey, oldCert, "Previous Mesh CA")
	_, currentCert := testCAWithParent(t, previousKey, previousCert, "Current Mesh CA")

	issuer := caBundleServer(t, currentCert, previousCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, oldCert)

	certs, err := client.refreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !sameCertificate(certs[0], currentCert) || !sameCertificate(certs[1], previousCert) {
		t.Fatalf("RefreshCABundle did not preserve published bundle order for continuity-signed chain")
	}
}

func TestRefreshCABundleRejectsReplacementWithoutOverlap(t *testing.T) {
	_, oldCert := testCA(t)
	_, replacementCert := testCA(t)

	issuer := caBundleServer(t, replacementCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, oldCert)

	_, err := client.refreshCABundle(context.Background())
	if err == nil {
		t.Fatal("RefreshCABundle accepted replacement bundle with no overlap")
	}
	if !strings.Contains(err.Error(), "no trusted CA continuity") {
		t.Fatalf("RefreshCABundle error = %v, want continuity rejection", err)
	}
}

func TestRefreshCABundleRejectsExpiredTrustedOnlyBundle(t *testing.T) {
	_, currentCert := testCA(t)
	_, expiredCert := testCAWithValidity(t, "Expired Mesh CA", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	issuer := caBundleServer(t, expiredCert)
	defer issuer.Close()

	client := NewClient(&Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	})
	seedTrustedCABundle(t, client, currentCert, expiredCert)

	_, err := client.refreshCABundle(context.Background())
	if err == nil {
		t.Fatal("RefreshCABundle accepted a bundle containing only an expired trusted CA")
	}
	if !strings.Contains(err.Error(), "no trusted CA continuity") {
		t.Fatalf("RefreshCABundle error = %v, want continuity rejection", err)
	}

	trusted := client.TrustedCABundle()
	if len(trusted) != 2 || !sameCertificate(trusted[0], currentCert) || !sameCertificate(trusted[1], expiredCert) {
		t.Fatalf("trusted CA bundle changed after rejected refresh, count=%d", len(trusted))
	}
}

func TestNewProviderValidation(t *testing.T) {
	base := Config{
		CDSURL:            "http://cds",
		AttestationApiURL: "http://attest",
		CDSCAURL:          "http://issuer",
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
	}

	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"missing CDSURL", func(c *Config) { c.CDSURL = "" }},
		{"missing AttestationApiURL", func(c *Config) { c.AttestationApiURL = "" }},
		{"missing CDSCAURL", func(c *Config) { c.CDSCAURL = "" }},
		{"missing NodeIP", func(c *Config) { c.NodeIP = "" }},
		{"invalid NodeIP", func(c *Config) { c.NodeIP = "not-an-ip" }},
		{"missing TEEType", func(c *Config) { c.TEEType = "" }},
		{"unsupported TEEType", func(c *Config) { c.TEEType = armtls.TEEType("nitro") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.modify(&cfg)
			_, err := NewProvider(&cfg, nil)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}
