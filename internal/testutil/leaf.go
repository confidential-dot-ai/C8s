package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// CheckLeafProfile asserts leaf carries what an issued leaf must: it certifies
// key, its NotBefore is the signing time (between before and after; x509
// encodes validity to the second, so before is truncated), its validity is
// ttl, it is not a CA, and it carries the serverAuth and clientAuth usages.
func CheckLeafProfile(t *testing.T, leaf *x509.Certificate, key *ecdsa.PublicKey, ttl time.Duration, before, after time.Time) {
	t.Helper()
	if !key.Equal(leaf.PublicKey) {
		t.Error("leaf certifies a key other than the CSR's")
	}
	before = before.Truncate(time.Second)
	if leaf.NotBefore.Before(before) || leaf.NotBefore.After(after) {
		t.Errorf("NotBefore %s is not the signing time (between %s and %s)", leaf.NotBefore, before, after)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != ttl {
		t.Errorf("validity %s, want the %s TTL", got, ttl)
	}
	if leaf.IsCA {
		t.Error("leaf is marked as a CA")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("leaf lacks the DigitalSignature key usage")
	}
	if want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}; !slices.Equal(leaf.ExtKeyUsage, want) {
		t.Errorf("extended key usage: got %v, want %v", leaf.ExtKeyUsage, want)
	}
}

// WriteLeaf stages a self-signed certificate and its key in dir as tls.crt and
// tls.key, where the cert sidecar leaves a leaf, and returns their paths and
// the key's public half.
func WriteLeaf(t *testing.T, dir string) (certPath, keyPath string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for path, block := range map[string]*pem.Block{
		certPath: {Type: "CERTIFICATE", Bytes: der},
		keyPath:  {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath, &key.PublicKey
}
