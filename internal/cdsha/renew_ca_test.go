package cdsha

import (
	"bytes"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// The leader renews the shared mesh CA certificate past half its lifetime,
// through the log: every replica ends up serving the same new certificate,
// under the same key, so workloads keep their trust anchor.
func TestLeaderRenewsTheMeshCACertificate(t *testing.T) {
	c := newCluster(t, 3)
	c.caValidity = 3 * time.Second
	c.genesis("n0", "n1", "n2")
	first := c.leader().node.fsm.CA().Cert
	eventually(t, 15*time.Second, "every replica on one renewed certificate", func() bool {
		var seen []byte
		for _, r := range c.live() {
			ca := r.node.fsm.CA()
			if ca == nil || bytes.Equal(ca.Cert.Raw, first.Raw) || (seen != nil && !bytes.Equal(ca.Cert.Raw, seen)) {
				return false
			}
			seen = ca.Cert.Raw
		}
		return seen != nil
	})
	renewed := c.leader().node.fsm.CA().Cert
	if !bytes.Equal(renewed.RawSubjectPublicKeyInfo, first.RawSubjectPublicKeyInfo) || !renewed.NotAfter.After(first.NotAfter) {
		t.Fatal("the renewal changed the key or did not extend the certificate")
	}
	if err := issuer.RenewalOf(first, renewed); err != nil {
		t.Fatal(err)
	}
	// The served status names the new certificate on every replica.
	fp := c.leader().node.Status().CAFingerprint
	for _, r := range c.live() {
		if r.node.Status().CAFingerprint != fp {
			t.Fatalf("%s reports another CA", r.name)
		}
	}
}

// A renewal entry is adopted only when it renews the current certificate:
// self-signed under the same key, same subject, a later expiry.
func TestApplyRenewCARefusals(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	apply := func(i uint64, e Entry) any { return applyAt(f, i, e) }
	mesh, err := issuer.NewMeshCA("c8s-mesh-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca := mesh.Current().CA
	if err, _ := apply(1, Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{RootCert: ca.Cert.Raw}}).(error); err == nil {
		t.Fatal("renewed a CA before there was one")
	}
	f.mu.Lock()
	f.ca, f.core.RootCert = ca, ca.Cert.Raw
	f.mu.Unlock()
	good, err := issuer.SelfSignCA(ca.Key, "c8s-mesh-ca", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := issuer.NewMeshCA("c8s-mesh-ca", 3*time.Hour)
	renamed, _ := issuer.SelfSignCA(ca.Key, "another-ca", 3*time.Hour)
	shorter, _ := issuer.SelfSignCA(ca.Key, "c8s-mesh-ca", time.Minute)
	for name, der := range map[string][]byte{
		"another key": other.Current().CA.Cert.Raw, "another subject": renamed.Raw, "a shorter life": shorter.Raw, "garbage": []byte("x"),
	} {
		if err, _ := apply(4, Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{RootCert: der}}).(error); err == nil {
			t.Fatalf("adopted %s", name)
		}
		if !bytes.Equal(f.CA().Cert.Raw, ca.Cert.Raw) {
			t.Fatalf("%s replaced the CA", name)
		}
	}
	if res := apply(5, Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{RootCert: good.Raw}}); res != nil {
		t.Fatalf("a valid renewal: %v", res)
	}
	if !bytes.Equal(f.CA().Cert.Raw, good.Raw) || !bytes.Equal(f.Core().RootCert, good.Raw) || f.CA().Key != ca.Key {
		t.Fatal("the renewal was not adopted under the same key")
	}
}
