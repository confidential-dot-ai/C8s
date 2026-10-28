package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// RenewalOf accepts only a later CA certificate self-signed under the same
// key with the same subject: what a replicated CDS lets its leader publish.
func TestRenewalOf(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	current, err := SelfSignCA(key, "mesh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	renewed, _ := SelfSignCA(key, "mesh", 2*time.Hour)
	if err := RenewalOf(current, renewed); err != nil {
		t.Fatalf("a valid renewal: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	// Same public key in the certificate, signed by another key.
	serial, _ := certutil.GenerateSerial()
	tmpl := certutil.NewCATemplate(serial, "mesh", time.Now().Add(3*time.Hour))
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, other)
	forged, _ := x509.ParseCertificate(der)
	// A leaf-shaped certificate under the same key.
	leafTmpl := certutil.NewCATemplate(serial, "mesh", time.Now().Add(3*time.Hour))
	leafTmpl.IsCA, leafTmpl.KeyUsage = false, x509.KeyUsageDigitalSignature
	der, _ = x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	notCA, _ := x509.ParseCertificate(der)
	otherKey, _ := SelfSignCA(other, "mesh", 3*time.Hour)
	renamed, _ := SelfSignCA(key, "other", 3*time.Hour)
	shorter, _ := SelfSignCA(key, "mesh", time.Minute)
	for name, c := range map[string]*x509.Certificate{
		"forged signature": forged, "not a CA": notCA, "another key": otherKey, "another subject": renamed, "shorter": shorter, "itself": current,
	} {
		if err := RenewalOf(current, c); err == nil {
			t.Errorf("%s accepted as a renewal", name)
		}
	}
}

// PastHalfLife is the renewal trigger: half the certificate's lifetime,
// leaving the rest of it for renewal to keep retrying in.
func TestPastHalfLife(t *testing.T) {
	now := time.Now()
	window := func(start, end time.Duration) *x509.Certificate {
		return &x509.Certificate{NotBefore: now.Add(start), NotAfter: now.Add(end)}
	}
	for name, c := range map[string]struct {
		cert *x509.Certificate
		want bool
	}{
		"fresh certificate":             {window(-time.Minute, time.Hour), false},
		"just before half its lifetime": {window(-29*time.Minute, 31*time.Minute), false},
		"past half its lifetime":        {window(-31*time.Minute, 29*time.Minute), true},
		"expired":                       {window(-2*time.Hour, -time.Hour), true},
	} {
		if got := PastHalfLife(c.cert, now); got != c.want {
			t.Errorf("%s: PastHalfLife = %v, want %v", name, got, c.want)
		}
	}
}
