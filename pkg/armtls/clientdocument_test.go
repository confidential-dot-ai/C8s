package armtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func certWithExtensions(t *testing.T, exts ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), ExtraExtensions: exts}
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

func TestClientDocumentDigestRoundTrip(t *testing.T) {
	h := sha256.Sum256([]byte("client document"))
	ext, err := MarshalClientDocumentDigestExtension(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if ext.Critical || !ext.Id.Equal(OIDClientDocumentDigest) {
		t.Fatalf("extension = %+v", ext)
	}
	got, ok := ClientDocumentDigest(certWithExtensions(t, ext))
	if !ok || !bytes.Equal(got, h[:]) {
		t.Fatalf("digest = %x %v", got, ok)
	}
	if _, ok := ClientDocumentDigest(certWithExtensions(t)); ok {
		t.Fatal("a certificate without the extension names a client document")
	}
	if _, err := MarshalClientDocumentDigestExtension(h[:31]); err == nil {
		t.Fatal("a short digest was marshalled")
	}
}

// A damaged or repeated extension names no client document.
func TestClientDocumentDigestRefusesMalformedExtensions(t *testing.T) {
	h := sha256.Sum256([]byte("client document"))
	good, err := MarshalClientDocumentDigestExtension(h[:])
	if err != nil {
		t.Fatal(err)
	}
	short, _ := asn1.Marshal(h[:16])
	utf8, _ := asn1.MarshalWithParams(string(h[:]), "utf8")
	longForm := append([]byte{0x04, 0x81, 0x20}, h[:]...)
	for name, exts := range map[string][]pkix.Extension{
		"repeated":            {good, {Id: OIDClientDocumentDigest, Value: good.Value}},
		"short":               {{Id: OIDClientDocumentDigest, Value: short}},
		"not an octet string": {{Id: OIDClientDocumentDigest, Value: utf8}},
		"trailing bytes":      {{Id: OIDClientDocumentDigest, Value: append(bytes.Clone(good.Value), 0)}},
		"noncanonical":        {{Id: OIDClientDocumentDigest, Value: longForm}},
	} {
		t.Run(name, func(t *testing.T) {
			// crypto/x509 refuses to parse a repeated extension, so the
			// parsed form is built directly.
			cert := &x509.Certificate{Extensions: exts}
			if _, ok := ClientDocumentDigest(cert); ok {
				t.Fatal("malformed extension accepted")
			}
			if _, err := clientDocumentDigestFromCert(cert); err == nil {
				t.Fatal("malformed extension read as absence")
			}
		})
	}
}

// The label is the lowercase unpadded base32 of the digest's first 16 bytes,
// so it changes with any change of the document.
func TestAgentLabel(t *testing.T) {
	h := make([]byte, 32)
	if got := AgentLabel(h); got != "aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("label = %q", got)
	}
	a, b := sha256.Sum256([]byte("client document")), sha256.Sum256([]byte("client document."))
	la, lb := AgentLabel(a[:]), AgentLabel(b[:])
	if len(la) != 26 || la == lb {
		t.Fatalf("labels %q %q", la, lb)
	}
	for _, c := range la {
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			t.Fatalf("label %q is not a lowercase base32 DNS label", la)
		}
	}
	h[15] = 0xff
	if got := AgentLabel(h); got != "aaaaaaaaaaaaaaaaaaaaaaaa74" {
		t.Fatalf("label = %q", got)
	}
}
