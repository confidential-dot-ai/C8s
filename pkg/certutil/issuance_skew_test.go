package certutil

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

// Exercise the normal X.509 verifier: changing its clock or allowing an
// expired certificate would conceal the cross-guest failure this guards.
func TestIssuedLeafWithIssuerClockAhead(t *testing.T) {
	now := time.Now()
	caKey, leafKey := newKey(t), newKey(t)
	ca := NewCATemplate(big.NewInt(1), "mesh", now.Add(time.Hour))
	ca.NotBefore = now.Add(-time.Hour)
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	tmpl, err := NewLeafTemplate("workload", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) != time.Hour || leaf.NotAfter.After(now.Add(time.Hour)) {
		t.Fatal("backdating extended the requested lifetime")
	}
	for _, tc := range []struct {
		name    string
		at      time.Time
		purpose x509.ExtKeyUsage
		want    bool
	}{
		{"one second behind issuer", now.Add(-time.Second), x509.ExtKeyUsageClientAuth, true},
		{"outside backdate", now.Add(-LeafValiditySkew - time.Minute), x509.ExtKeyUsageClientAuth, false},
		{"expired", leaf.NotAfter.Add(time.Second), x509.ExtKeyUsageClientAuth, false},
		{"wrong purpose", now, x509.ExtKeyUsageCodeSigning, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: tc.at, KeyUsages: []x509.ExtKeyUsage{tc.purpose}})
			if (err == nil) != tc.want {
				t.Fatalf("verification = %v, want pass %v", err, tc.want)
			}
		})
	}
}

func TestIssuedLeafShortTTLRetainsLifetime(t *testing.T) {
	for _, ttl := range []time.Duration{time.Second, time.Minute, time.Hour} {
		before := time.Now()
		leaf, err := NewLeafTemplate("short", ttl)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.NotAfter.Sub(leaf.NotBefore) != ttl || leaf.NotAfter.Before(before.Add(ttl-ttl/10)) {
			t.Fatalf("TTL %s lost more than one tenth of its remaining lifetime", ttl)
		}
	}
}
