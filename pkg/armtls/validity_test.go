package armtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// attestedCertWithWindow mints a self-signed ARmTLS certificate carrying a
// well-formed attestation extension but the given validity window, so tests
// can put genuine-looking evidence inside an unacceptable window.
func attestedCertWithWindow(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, att := testKeyAndAttestation(t)
	ext, err := MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(600),
		Subject:         pkix.Name{CommonName: "windowed-armtls"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerifyCertEnforcesValidity(t *testing.T) {
	now := time.Now()

	t.Run("expired rejected before the evidence round-trip", func(t *testing.T) {
		stub := mockapi.New(t)
		cert := attestedCertWithWindow(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL()}, nil)
		if !errors.Is(err, ErrCertValidity) {
			t.Fatalf("err = %v, want errors.Is ErrCertValidity", err)
		}
		if got := len(stub.VerifyRequests()); got != 0 {
			t.Fatalf("an expired certificate consumed %d attestation-api call(s), want 0", got)
		}
	})

	t.Run("not yet valid beyond skew rejected", func(t *testing.T) {
		stub := mockapi.New(t)
		cert := attestedCertWithWindow(t, now.Add(certutil.LeafValiditySkew+time.Minute), now.Add(2*time.Hour))
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL()}, nil)
		if !errors.Is(err, ErrCertValidity) {
			t.Fatalf("err = %v, want errors.Is ErrCertValidity", err)
		}
		if got := len(stub.VerifyRequests()); got != 0 {
			t.Fatalf("a not-yet-valid certificate consumed %d attestation-api call(s), want 0", got)
		}
	})

	t.Run("NotBefore within skew accepted", func(t *testing.T) {
		measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(measurement)))
		cert := attestedCertWithWindow(t, now.Add(certutil.LeafValiditySkew-time.Minute), now.Add(2*time.Hour))
		if _, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: [][]byte{measurement}}}, nil); err != nil {
			t.Fatalf("NotBefore within the skew allowance must pass: %v", err)
		}
	})
}

// The dual verifier's ARmTLS fallback accepts a self-signed peer on its
// evidence alone; the validity window is the only freshness bound that
// evidence has, so an expired peer must be refused — and cheaply, before any
// attestation-api round-trip.
func TestDualVerifyPeerCallbackRejectsExpiredSelfSigned(t *testing.T) {
	stub := mockapi.New(t)
	cert := attestedCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	_, caCert := generateCACert(t)

	verify := dualVerifyPeerCallback(
		&VerifyPolicy{AttestationApiURL: stub.URL()},
		newSharedCACerts([]*x509.Certificate{caCert}),
	)
	err := verify([][]byte{cert.Raw}, nil)
	if !errors.Is(err, ErrCertValidity) {
		t.Fatalf("err = %v, want errors.Is ErrCertValidity", err)
	}
	if got := len(stub.VerifyRequests()); got != 0 {
		t.Fatalf("an expired peer consumed %d attestation-api call(s), want 0", got)
	}
}

// The CA branch of the dual verifier delegates validity to x509.Verify at
// time.Now. This pins that property: an expired leaf with an otherwise
// perfect CA chain must not pass.
func TestDualVerifyPeerCallbackRejectsExpiredCASigned(t *testing.T) {
	caKey, caCert := generateCACert(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(601),
		Subject:      pkix.Name{CommonName: "expired-leaf"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	verify := dualVerifyPeerCallback(&VerifyPolicy{}, newSharedCACerts([]*x509.Certificate{caCert}))
	if err := verify([][]byte{der}, nil); err == nil {
		t.Fatal("expired CA-signed peer was accepted")
	}
}

// erroringProvider models a certificate source that is down — the shape of a
// rotation outage.
type erroringProvider struct{ err error }

func (p *erroringProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	return nil, 0, p.err
}

// simpleCertWithWindow is generateSimpleCert with a caller-chosen window.
func simpleCertWithWindow(t *testing.T, notBefore, notAfter time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(602),
		Subject:      pkix.Name{CommonName: "windowed"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// A cached certificate past NotAfter must never reach a handshake: with the
// provider down, the handshake gets the provisioning error, not the stale
// cert; once the provider recovers, the stale cert is replaced synchronously.
func TestGetOrProvisionRefusesExpiredCachedCert(t *testing.T) {
	expired := simpleCertWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	provisionErr := errors.New("certificate source down")
	// syncCooldown is minimal so the recovery step below is observable
	// immediately; the negative cache has its own test.
	s := &certState{provider: &erroringProvider{err: provisionErr}, syncCooldown: time.Nanosecond}
	s.cert = expired
	// Rotation not even due yet — expiry must be a hard stop on its own.
	s.rotateAt = time.Now().Add(time.Hour)

	if _, err := s.getOrProvision(context.Background()); !errors.Is(err, provisionErr) {
		t.Fatalf("err = %v, want the provisioning error (and never the expired cert)", err)
	}

	// Provider recovers: the expired cert is replaced, not served.
	fresh := generateSimpleCert(t)
	s.mu.Lock()
	s.provider = &mockProvider{cert: fresh, ttl: time.Hour}
	s.mu.Unlock()

	got, err := s.getOrProvision(context.Background())
	if err != nil {
		t.Fatalf("recovered provider: %v", err)
	}
	if got != fresh {
		t.Fatal("expected the freshly provisioned cert, not the expired cached one")
	}
	// And the fresh cert is cached for subsequent handshakes.
	if again, err := s.getOrProvision(context.Background()); err != nil || again != fresh {
		t.Fatalf("cached fresh cert not served: cert=%v err=%v", again, err)
	}
}

// A cached certificate whose NotBefore is beyond the shared skew allowance is
// as unusable as an expired one.
func TestGetOrProvisionRefusesNotYetValidCachedCert(t *testing.T) {
	future := simpleCertWithWindow(t,
		time.Now().Add(certutil.LeafValiditySkew+time.Hour), time.Now().Add(3*time.Hour))
	provisionErr := errors.New("certificate source down")
	s := &certState{provider: &erroringProvider{err: provisionErr}}
	s.cert = future
	s.rotateAt = time.Now().Add(time.Hour)

	if _, err := s.getOrProvision(context.Background()); !errors.Is(err, provisionErr) {
		t.Fatalf("err = %v, want the provisioning error (and never the not-yet-valid cert)", err)
	}
}

// caSignedLeaf mints a leaf signed by ca with the given window.
func caSignedLeaf(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(603),
		Subject:      pkix.Name{CommonName: "skewed-leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The two branches of the dual verifier must share one validity window.
// x509.Verify grants no NotBefore skew of its own, so a CA-signed leaf minted
// a few minutes into the verifier's future used to fail the chain branch and
// fall through to ARmTLS — where the sandbox and workload pins are not
// enforced at all. The skew is granted at the NotBefore end only.
func TestDualVerifyPeerCallbackSharesTheSkewWindow(t *testing.T) {
	caKey, caCert := generateCACert(t)
	shared := newSharedCACerts([]*x509.Certificate{caCert})
	now := time.Now()

	t.Run("NotBefore within skew takes the chain branch", func(t *testing.T) {
		der := caSignedLeaf(t, caKey, caCert, now.Add(2*time.Minute), now.Add(time.Hour))
		if err := dualVerifyPeerCallback(&VerifyPolicy{}, shared)([][]byte{der}, nil); err != nil {
			t.Fatalf("a within-skew CA-signed leaf was not accepted on the chain branch: %v", err)
		}
	})

	t.Run("chain branch still enforces the pins", func(t *testing.T) {
		der := caSignedLeaf(t, caKey, caCert, now.Add(2*time.Minute), now.Add(time.Hour))
		policy := &VerifyPolicy{SandboxID: "pod-abc"}
		err := dualVerifyPeerCallback(policy, shared)([][]byte{der}, nil)
		if err == nil {
			t.Fatal("a leaf with no sandbox-ID extension satisfied a sandbox pin")
		}
		// The chain branch's own rejection, not the ARmTLS fallback's "pin
		// requires a CA-verified certificate" — that difference IS the bug.
		if !strings.Contains(err.Error(), "CA-signed peer failed the sandbox-ID pin") {
			t.Fatalf("err = %v, want the chain branch's pin rejection (the leaf fell through to ARmTLS)", err)
		}
	})

	t.Run("the skew does not extend NotAfter", func(t *testing.T) {
		der := caSignedLeaf(t, caKey, caCert, now.Add(-time.Hour), now.Add(-time.Minute))
		err := dualVerifyPeerCallback(&VerifyPolicy{}, shared)([][]byte{der}, nil)
		if err == nil {
			t.Fatal("a leaf one minute past NotAfter was accepted")
		}
	})
}

// VerifyCert is the mesh's highest-traffic self-signed path and is exported
// for certificates that arrive as data, not only from handshakes. The
// attestation extension binds only the public key, so a self-issued leaf must
// verify its body under that key — otherwise subject, serial and validity are
// rewritable under a genuine attestation. That check belongs here, not only
// in the callers that happen to run certutil.AuthenticateLeafBody themselves.
func TestVerifyCertAuthenticatesTheLeafBody(t *testing.T) {
	stub := mockapi.New(t)
	now := time.Now()

	// Same attested key, body signed by a different key: a self-issued leaf
	// whose signature was never anyone's to make.
	key, att := testKeyAndAttestation(t)
	ext, err := MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(604),
		Subject:         pkix.Name{CommonName: "re-signed-armtls"},
		NotBefore:       now.Add(-time.Hour),
		NotAfter:        now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL()}, nil)
	if err == nil || !strings.Contains(err.Error(), "does not verify with its own key") {
		t.Fatalf("err = %v, want the self-signature rejection", err)
	}
	if got := len(stub.VerifyRequests()); got != 0 {
		t.Fatalf("a re-signed body consumed %d attestation-api call(s), want 0", got)
	}
}
