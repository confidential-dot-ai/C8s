package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// selfSignatureOK is the check certutil.AuthenticateLeafBody applies to a
// self-issued leaf. x509.CheckSignatureFrom would refuse the parent on its
// basic constraints before looking at the signature, so it cannot tell a
// rewritten body from an intact one.
func selfSignatureOK(cert *x509.Certificate) bool {
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func TestRewriteNotAfter(t *testing.T) {
	original := testCert(t, certOptions{notAfter: 24 * time.Hour}).Leaf
	if !selfSignatureOK(original) {
		t.Fatal("the unmodified certificate must verify under its own key")
	}

	target := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	der, err := rewriteNotAfter(original.Raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) != len(original.Raw) {
		t.Fatalf("length changed from %d to %d", len(original.Raw), len(der))
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("rewritten certificate does not parse: %v", err)
	}
	if !cert.NotAfter.Equal(target) {
		t.Fatalf("NotAfter = %s, want %s", cert.NotAfter, target)
	}
	if !cert.NotBefore.Equal(original.NotBefore) || !bytes.Equal(cert.Signature, original.Signature) {
		t.Fatal("rewrite touched more than NotAfter")
	}
	if selfSignatureOK(cert) {
		t.Fatal("the rewritten body still verifies under its own key")
	}
	if _, err := rewriteNotAfter(original.Raw, time.Date(2060, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("a time outside UTCTime's range must be refused, not re-encoded")
	}
	if _, err := rewriteNotAfter([]byte{0x30, 0x03, 0x02, 0x01}, target); err == nil {
		t.Fatal("truncated DER must be refused")
	}
}

func TestIssuerDiffers(t *testing.T) {
	cert := testCert(t, certOptions{notAfter: time.Hour, issuerDiffers: true}).Leaf
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		t.Fatalf("issuer %q equals subject %q", cert.Issuer, cert.Subject)
	}
	if selfSignatureOK(cert) {
		t.Fatal("certificate verifies under its own key, so it is not signed by an unrelated one")
	}
	att, err := armtls.ExtractAttestation(cert)
	if err != nil {
		t.Fatalf("evidence extension: %v", err)
	}
	if att.Family != armtls.TEETypeSEVSNP || !bytes.Equal(att.Report, fakeReport()) {
		t.Fatalf("extension = %+v", att)
	}
	plain := testCert(t, certOptions{notAfter: time.Hour}).Leaf
	if !bytes.Equal(plain.RawIssuer, plain.RawSubject) || !selfSignatureOK(plain) {
		t.Fatal("without issuerDiffers the certificate must be self-signed")
	}
}

func TestBuildCertWindow(t *testing.T) {
	now := time.Now()
	cert := testCert(t, certOptions{notBefore: time.Hour, notAfter: 2 * time.Hour}).Leaf
	if cert.NotBefore.Before(now.Add(59*time.Minute)) || cert.NotAfter.Before(now.Add(119*time.Minute)) {
		t.Fatalf("window %s..%s does not follow the offsets", cert.NotBefore, cert.NotAfter)
	}
}

// TestSelfSignedCertUnixSocket serves a mock /attest on a Unix socket, the
// way the node's attestation API reaches a pod, and checks the minted
// certificate carries the report bound to its own key.
func TestSelfSignedCertUnixSocket(t *testing.T) {
	const reportDataOffset = 0x50
	socket := filepath.Join(t.TempDir(), "a.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/attest" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var req remote.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if len(req.ReportData) != sha512.Size384 {
			t.Errorf("report data is %d bytes, want the 48 the mesh sends", len(req.ReportData))
		}
		rep := fakeReport()
		copy(rep[reportDataOffset:], req.ReportData)
		evidence, _ := json.Marshal(map[string]string{"attestation_report": base64.StdEncoding.EncodeToString(rep)})
		json.NewEncoder(w).Encode(remote.AttestResponse{Platform: teetypes.PlatformSNP, Evidence: evidence})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	cert, err := selfSignedCert(context.Background(), certOptions{
		attestationURL: "unix://" + socket,
		platform:       "sev-snp",
		notAfter:       time.Hour,
		timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	att, err := armtls.ExtractAttestation(cert.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	want, err := armtls.ReportDataForKey(cert.Leaf.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if att.Family != armtls.TEETypeSEVSNP || len(att.Report) != len(fakeReport()) ||
		!bytes.Equal(att.Report[reportDataOffset:reportDataOffset+64], want[:]) {
		t.Fatalf("extension does not carry the raw report bound to the key: family %v, %d bytes", att.Family, len(att.Report))
	}
	if !selfSignatureOK(cert.Leaf) {
		t.Fatal("minted certificate must be self-signed")
	}

	if _, err := selfSignedCert(context.Background(), certOptions{attestationURL: "unix://" + socket, platform: "sgx", timeout: time.Second}); err == nil {
		t.Fatal("an unknown platform must fail before any evidence is fetched")
	}
}
