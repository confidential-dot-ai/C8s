package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// stampedLeaf mints a leaf carrying the given extensions. Nothing vouches for
// them here; applyWorkloadPolicy decides what it says about their provenance.
func stampedLeaf(t *testing.T, exts ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func testStamp(t *testing.T) (*armtls.ComponentSet, pkix.Extension) {
	t.Helper()
	set := &armtls.ComponentSet{Version: "0.43.0", Digest: bytes.Repeat([]byte{0x22}, 32)}
	ext, err := armtls.MarshalComponentSetExtension(set)
	if err != nil {
		t.Fatal(err)
	}
	return set, ext
}

// The set the leaf names reaches the verdict and the printed report, and a
// failed verdict surfaces nothing.
func TestApplyWorkloadPolicyReportsTheComponentSet(t *testing.T) {
	set, ext := testStamp(t)
	ev := &evidence{leaf: stampedLeaf(t, ext)}

	oc := Outcome{Verified: true}
	applyWorkloadPolicy(&oc, config{}, ev, nil)
	if oc.ComponentSet != set.Version || oc.ComponentSetDigest != hex.EncodeToString(set.Digest) {
		t.Fatalf("component set = %q %q, want %q %x", oc.ComponentSet, oc.ComponentSetDigest, set.Version, set.Digest)
	}
	var out bytes.Buffer
	renderText(config{}, oc, &out)
	if !strings.Contains(out.String(), "component set: 0.43.0") {
		t.Fatalf("report does not name the component set:\n%s", out.String())
	}

	failed := Outcome{Verified: false}
	applyWorkloadPolicy(&failed, config{}, ev, nil)
	if failed.ComponentSet != "" {
		t.Fatalf("ComponentSet = %q on a failed verdict, want empty", failed.ComponentSet)
	}
}

// A leaf without the stamp reports no set, and a damaged one fails the verdict
// rather than reading as absence.
func TestApplyWorkloadPolicyComponentSetBoundaries(t *testing.T) {
	oc := Outcome{Verified: true}
	applyWorkloadPolicy(&oc, config{}, &evidence{leaf: stampedLeaf(t)}, nil)
	if oc.ComponentSet != "" || !oc.Verified {
		t.Fatalf("an unstamped leaf reported %q, verified = %v", oc.ComponentSet, oc.Verified)
	}

	_, ext := testStamp(t)
	ext.Value = ext.Value[:len(ext.Value)-1]
	damaged := Outcome{Verified: true}
	applyWorkloadPolicy(&damaged, config{}, &evidence{leaf: stampedLeaf(t, ext)}, nil)
	if damaged.Verified || !strings.Contains(damaged.Error, "component_set_malformed") {
		t.Fatalf("a damaged stamp left the verdict at verified = %v, error = %q", damaged.Verified, damaged.Error)
	}
}
