package issuer_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Renewal is the continuity contract: a leaf signed before it still chains to
// the certificate published after it.
func TestMeshCARenewalKeepsLeavesChaining(t *testing.T) {
	mesh, err := issuer.NewMeshCA("mesh ca", time.Hour)
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	before := mesh.Current()
	csr, _ := mustCSR(t, "leaf", nil, nil, nil)
	leafPEM, _, err := before.CA.SignCSR(issuer.SignCSRParams{
		CSR: csr,
		TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	renewed, err := mesh.RenewCertificate()
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(renewed.CA.Cert)
	leaf, err := certutil.ParseCertificatePEM(leafPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("leaf issued under the previous certificate does not chain to the renewed one: %v", err)
	}
}

// The fields a chain is matched on survive renewal; the certificate itself
// does not.
func TestMeshCARenewalPreservesIdentity(t *testing.T) {
	mesh, err := issuer.NewMeshCA("mesh ca", time.Hour)
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	before := mesh.Current().CA.Cert

	renewed, err := mesh.RenewCertificate()
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}

	if !renewed.CA.Cert.Equal(mesh.Current().CA.Cert) {
		t.Fatal("Current does not return the renewed certificate")
	}
	if !bytes.Equal(renewed.CA.Cert.RawSubject, before.RawSubject) {
		t.Error("subject changed")
	}
	if !bytes.Equal(renewed.CA.Cert.SubjectKeyId, before.SubjectKeyId) {
		t.Error("subject key identifier changed")
	}
	if !renewed.CA.Cert.PublicKey.(*ecdsa.PublicKey).Equal(before.PublicKey) {
		t.Error("public key changed: the CA key must outlive its certificate")
	}
	if renewed.CA.Cert.KeyUsage != before.KeyUsage || !renewed.CA.Cert.IsCA {
		t.Error("signing capabilities changed")
	}
	if renewed.CA.Cert.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Error("renewal reused the previous serial")
	}
	if renewed.CA.Cert.NotAfter.Before(before.NotAfter) {
		t.Error("renewed certificate expires before the one it replaces")
	}
	if !bytes.Equal(renewed.CertPEM, mesh.Current().CertPEM) {
		t.Error("published PEM does not match the renewed certificate")
	}
}

// The constructor is the only place a mesh CA comes from, so a caller cannot
// get one with no name or no lifetime.
func TestNewMeshCARejectsIncompleteParameters(t *testing.T) {
	if _, err := issuer.NewMeshCA("", time.Hour); err == nil {
		t.Error("NewMeshCA accepted an empty common name")
	}
	if _, err := issuer.NewMeshCA("mesh ca", 0); err == nil {
		t.Error("NewMeshCA accepted a zero validity")
	}
	if _, err := issuer.NewMeshCA("mesh ca", -time.Hour); err == nil {
		t.Error("NewMeshCA accepted a negative validity")
	}
}
