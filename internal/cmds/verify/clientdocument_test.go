package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func clientDocumentLeaf(t *testing.T, document []byte) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(document)
	ext, err := armtls.MarshalClientDocumentDigestExtension(h[:])
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "pod"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{ext}}
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

// The digest and agent label are reported with what vouches for them, and
// --client-document fails the verdict unless the leaf names exactly that
// document.
func TestApplyClientDocumentPolicy(t *testing.T) {
	document := []byte("client document")
	ev := &evidence{leaf: clientDocumentLeaf(t, document)}
	h := sha256.Sum256(document)

	oc := Outcome{Verified: true}
	applyClientDocumentPolicy(&oc, config{}, ev)
	if oc.ClientDocumentDigest == "" || oc.AgentLabel != armtls.AgentLabel(h[:]) || !strings.Contains(oc.ClientDocumentNote, "not verified") {
		t.Fatalf("outcome = %+v", oc)
	}

	dir := t.TempDir()
	pin := func(name string, data []byte) config {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return config{clientDocument: path, meshCA: "checked by applySandboxPolicy"}
	}
	oc = Outcome{Verified: true}
	applyClientDocumentPolicy(&oc, pin("same", document), ev)
	if !oc.Verified || !strings.Contains(oc.ClientDocumentNote, "matches --client-document") {
		t.Fatalf("matching document: %+v", oc)
	}
	oc = Outcome{Verified: true}
	applyClientDocumentPolicy(&oc, pin("tampered", []byte("client document.")), ev)
	if oc.Verified || !strings.Contains(oc.Error, "client_document_mismatch") {
		t.Fatalf("tampered document: %+v", oc)
	}
	oc = Outcome{Verified: true}
	applyClientDocumentPolicy(&oc, pin("absent", document), &evidence{leaf: attestedCert(t, "")})
	if oc.Verified || !strings.Contains(oc.Error, "client_document_absent") {
		t.Fatalf("leaf without a digest: %+v", oc)
	}
}
