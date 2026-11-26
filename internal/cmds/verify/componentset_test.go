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

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
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

// The set the leaf names reaches the verdict and the printed report under the
// note that says what vouches for it, and a failed verdict surfaces nothing.
func TestApplyWorkloadPolicyReportsTheComponentSet(t *testing.T) {
	set, ext := testStamp(t)
	ev := &evidence{leaf: stampedLeaf(t, ext)}

	oc := Outcome{Verified: true}
	applyWorkloadPolicy(&oc, config{}, ev, nil)
	if oc.ComponentSet != set.Version || oc.ComponentSetDigest != hex.EncodeToString(set.Digest) {
		t.Fatalf("component set = %q %q, want %q %x", oc.ComponentSet, oc.ComponentSetDigest, set.Version, set.Digest)
	}
	if oc.ComponentSetNote != componentSetUnverifiedNote {
		t.Fatalf("note = %q, want the unverified one without --mesh-ca", oc.ComponentSetNote)
	}
	var out bytes.Buffer
	renderText(config{}, oc, &out)
	if !strings.Contains(out.String(), "component set: 0.43.0") || !strings.Contains(out.String(), componentSetUnverifiedNote) {
		t.Fatalf("report does not name the component set and what vouches for it:\n%s", out.String())
	}

	vouched := Outcome{Verified: true}
	applyWorkloadPolicy(&vouched, config{meshCA: "ca.pem"}, ev, nil)
	if !strings.HasPrefix(vouched.ComponentSetNote, "ca-vouched:") {
		t.Fatalf("note = %q, want the CA-vouched one", vouched.ComponentSetNote)
	}

	failed := Outcome{Verified: false}
	applyWorkloadPolicy(&failed, config{}, ev, nil)
	if failed.ComponentSet != "" || failed.ComponentSetNote != "" {
		t.Fatalf("component set = %q, note = %q on a failed verdict, want empty", failed.ComponentSet, failed.ComponentSetNote)
	}
}

// A hard failure states no passed check: the CA-vouched set is dropped, and the
// unverified one survives with the value it qualifies, as the sandbox ID and
// the workload stamp do.
func TestFinalNotesKeepOnlyTheUnverifiedComponentSet(t *testing.T) {
	set, ext := testStamp(t)
	ev := &evidence{leaf: stampedLeaf(t, ext)}
	plan := &verifyPlan{}
	result := &teetypes.VerificationResult{}

	unverified := Outcome{Verified: true}
	applyWorkloadPolicy(&unverified, config{}, ev, nil)
	unverified.Error = "a later check failed"
	applyFinalNotes(&unverified, ev, result, plan)
	if unverified.ComponentSet != set.Version || unverified.ComponentSetNote != componentSetUnverifiedNote {
		t.Fatalf("set = %q, note = %q, want both kept", unverified.ComponentSet, unverified.ComponentSetNote)
	}

	vouched := Outcome{Verified: true}
	applyWorkloadPolicy(&vouched, config{meshCA: "ca.pem"}, ev, nil)
	vouched.Error = "a later check failed"
	applyFinalNotes(&vouched, ev, result, plan)
	if vouched.ComponentSet != "" || vouched.ComponentSetDigest != "" || vouched.ComponentSetNote != "" {
		t.Fatalf("set = %q, digest = %q, note = %q, want all cleared", vouched.ComponentSet, vouched.ComponentSetDigest, vouched.ComponentSetNote)
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
