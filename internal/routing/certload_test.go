package routing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// leafPEM mints a CA-signed leaf valid over [notBefore, notAfter].
func leafPEM(t *testing.T, ca *issuer.CA, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "router"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	if leaf, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	if keyPEM, err = certutil.MarshalECKeyPEM(key); err != nil {
		t.Fatal(err)
	}
	return certutil.EncodeCertPEM(der), keyPEM, leaf
}

// TestMeshIdentityReloadsAndEnforcesValidity covers B4 across rotation: the
// mesh credential is get-cert-managed and rotates under a long-lived process.
func TestMeshIdentityReloadsAndEnforcesValidity(t *testing.T) {
	ca := newCA(t, "mesh")
	now := time.Now()
	dir := t.TempDir()
	certPEM, keyPEM, _ := leafPEM(t, ca, now.Add(-2*time.Hour), now.Add(-time.Hour))
	publishGeneration(t, dir, certPEM, keyPEM, []byte(caPEM(ca)))

	identity, err := NewMeshIdentity(volumePaths(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Credential(); err == nil {
		t.Fatal("Credential() with an expired credential = nil error, want one")
	}

	certPEM, keyPEM, fresh := leafPEM(t, ca, now.Add(-time.Minute), now.Add(time.Hour))
	publishGeneration(t, dir, certPEM, keyPEM, []byte(caPEM(ca)))
	got, err := identity.Credential()
	if err != nil {
		t.Fatalf("Credential() after rotation = %v, want nil", err)
	}
	if !got.Certificate.Leaf.Equal(fresh) {
		t.Fatal("Credential() served a leaf other than the rotated one")
	}
}

// The leaf and the mesh CAs of one credential come from the generation the
// pointer names. get-cert replaces the stable reader paths one by one, so a CA
// renewal reaches them before the pointer names the generation it belongs to;
// that CA anchors nothing until it does.
func TestMeshIdentityTakesLeafAndCAFromOneGeneration(t *testing.T) {
	published := newCA(t, "mesh")
	renewed := newCA(t, "mesh-2")
	now := time.Now()
	dir := t.TempDir()
	certPEM, keyPEM, leaf := leafPEM(t, published, now.Add(-time.Minute), now.Add(time.Hour))
	publishGeneration(t, dir, certPEM, keyPEM, []byte(caPEM(published)))
	identity, err := NewMeshIdentity(volumePaths(dir))
	if err != nil {
		t.Fatal(err)
	}

	renewedCertPEM, renewedKeyPEM, renewedLeaf := leafPEM(t, renewed, now.Add(-time.Minute), now.Add(time.Hour))
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, []byte(caPEM(renewed)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := identity.Credential()
	if err != nil {
		t.Fatalf("Credential() = %v, want nil", err)
	}
	if !got.Certificate.Leaf.Equal(leaf) {
		t.Error("Credential() served a leaf the pointer does not name")
	}
	if len(got.MeshCAs) != 1 || !got.MeshCAs[0].Equal(published.Cert) {
		t.Errorf("Credential() trusts %v, want the CA published with the leaf", got.MeshCAs)
	}

	publishGeneration(t, dir, renewedCertPEM, renewedKeyPEM, []byte(caPEM(renewed)))
	got, err = identity.Credential()
	if err != nil {
		t.Fatalf("Credential() after the renewal was published = %v, want nil", err)
	}
	if !got.Certificate.Leaf.Equal(renewedLeaf) || len(got.MeshCAs) != 1 || !got.MeshCAs[0].Equal(renewed.Cert) {
		t.Error("Credential() did not move to the generation the pointer names")
	}
}

// A withdrawn pointer leaves the router with no credential, even while the
// reader paths of the withdrawn generation are still readable.
func TestMeshIdentityRefusesAWithdrawnGeneration(t *testing.T) {
	ca := newCA(t, "mesh")
	now := time.Now()
	dir := t.TempDir()
	certPEM, keyPEM, _ := leafPEM(t, ca, now.Add(-time.Minute), now.Add(time.Hour))
	publishGeneration(t, dir, certPEM, keyPEM, []byte(caPEM(ca)))
	identity, err := NewMeshIdentity(volumePaths(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Credential(); err != nil {
		t.Fatalf("Credential() = %v, want nil", err)
	}
	if err := os.Remove(filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Credential(); err == nil {
		t.Fatal("Credential() after the withdrawal = nil error, want one")
	}
}
