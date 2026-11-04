package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// The cluster's mesh CA certificate is renewed through the log, under the one
// key the cluster holds, so the leaves issued under it keep their anchor.

// selfSignedCA is a CA certificate under key, named commonName.
func selfSignedCA(t *testing.T, key *ecdsa.PrivateKey, commonName string) []byte {
	t.Helper()
	serial, err := certutil.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := certutil.NewCATemplate(serial, commonName, time.Now().Add(time.Hour))
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A renewal is due at half the certificate's life, which leaves the cluster
// the other half to commit one in.
func TestARenewalIsDueAtHalfTheCertificatesLife(t *testing.T) {
	now := time.Now()
	for name, cert := range map[string]*x509.Certificate{
		"inside its first half": {
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(3 * time.Hour),
		},
		"past its first half": {
			NotBefore: now.Add(-3 * time.Hour),
			NotAfter:  now.Add(time.Hour),
		},
	} {
		t.Run(name, func(t *testing.T) {
			due := name == "past its first half"
			if pastHalfLife(cert, now) != due {
				t.Fatalf("a certificate %s is due for renewal: %v", name, !due)
			}
		})
	}
}

// A renewed certificate names the issuer the cluster's live leaves name: the
// same subject, the same key, and a later expiry.
func TestARenewedCertificateNamesTheSameIssuer(t *testing.T) {
	ca := mintCA(t)

	der, err := renewedMeshCert(ca)
	if err != nil {
		t.Fatalf("renew the mesh CA certificate: %v", err)
	}

	renewed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case !bytes.Equal(renewed.RawSubject, ca.Cert.RawSubject):
		t.Fatal("the renewed certificate names another subject")
	case !bytes.Equal(renewed.SubjectKeyId, ca.Cert.SubjectKeyId):
		t.Fatal("the renewed certificate names another subject key")
	case !renewed.PublicKey.(*ecdsa.PublicKey).Equal(&ca.Key.PublicKey):
		t.Fatal("the renewed certificate speaks for another key")
	case renewed.SerialNumber.Cmp(ca.Cert.SerialNumber) == 0:
		t.Fatal("the renewed certificate carries the serial of the one it replaces")
	case lifetimeOf(renewed) != lifetimeOf(ca.Cert):
		t.Fatalf("the renewed certificate lasts %s, the one it replaces %s", lifetimeOf(renewed), lifetimeOf(ca.Cert))
	case pastHalfLife(renewed, time.Now()):
		t.Fatal("the renewed certificate is due for renewal itself")
	}
}

// Every replica installs the certificate the log carries, under the key it
// already holds, and the cluster's version does not move: a renewal is no
// operator command.
func TestEveryReplicaServesTheRenewedMeshCACertificate(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	version := leader.node.fsm.ClusterState().Version
	key := leader.node.fsm.CA().Key
	renewed, err := renewedMeshCert(leader.node.fsm.CA())
	if err != nil {
		t.Fatal(err)
	}

	c.commitRaw(leader, marshalled(t, Entry{
		Kind:    KindRenewCA,
		RenewCA: &RenewCAEntry{MeshCACert: renewed},
	}))

	for _, r := range c.replicas {
		c.caughtUp(r, leader, 10*time.Second)
		core := r.node.fsm.ClusterState()
		ca := r.node.fsm.CA()
		switch {
		case r.node.fsm.Stuck() != "":
			t.Fatalf("replica %s stopped following the log: %s", r.node.member, r.node.fsm.Stuck())
		case !bytes.Equal(core.MeshCACert, renewed):
			t.Fatalf("replica %s holds another mesh CA certificate", r.node.member)
		case !bytes.Equal(ca.Cert.Raw, renewed):
			t.Fatalf("replica %s signs leaves under another certificate than it holds", r.node.member)
		case !ca.Key.PublicKey.Equal(&key.PublicKey):
			t.Fatalf("replica %s holds another mesh CA key", r.node.member)
		case core.Version != version:
			t.Fatalf("replica %s moved to version %d", r.node.member, core.Version)
		}
	}
}

// A certificate that is not the cluster's own, signed again, is one no
// replica can serve: it stops rather than answering with an anchor the rest
// of the cluster does not have.
func TestACertificateThatIsNotTheClustersOwnStopsTheReplica(t *testing.T) {
	for name, renewal := range map[string]func(t *testing.T, ca *issuer.CA) []byte{
		"bytes that are no certificate": func(*testing.T, *issuer.CA) []byte {
			return []byte("not a certificate")
		},
		"a certificate of another key": func(t *testing.T, _ *issuer.CA) []byte {
			return mintCA(t).Cert.Raw
		},
		"a certificate of another name": func(t *testing.T, ca *issuer.CA) []byte {
			return selfSignedCA(t, ca.Key, "another mesh")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newReplica(t)
			r.genesis()
			held := r.ClusterState().MeshCACert

			res := r.apply(Entry{
				Kind:    KindRenewCA,
				RenewCA: &RenewCAEntry{MeshCACert: renewal(t, r.CA())},
			})

			if res.Stop == nil || r.Stuck() == "" {
				t.Fatalf("the replica took %s: %+v", name, res)
			}
			if !bytes.Equal(r.ClusterState().MeshCACert, held) {
				t.Fatal("the replica replaced the mesh CA certificate it holds")
			}
		})
	}
}
