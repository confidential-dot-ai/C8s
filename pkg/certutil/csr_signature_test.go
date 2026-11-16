package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestParseAndVerifyCSRRejectsParseableInvalidSignature(t *testing.T) {
	block, _ := pem.Decode(ecdsaCSRPEM(t))
	if block == nil {
		t.Fatal("fixture is not PEM")
	}
	block.Bytes[len(block.Bytes)-1] ^= 1
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("invalid-signature fixture must still parse: %v", err)
	}
	if err := request.CheckSignature(); err == nil {
		t.Fatal("fixture signature is valid")
	}

	csr, err := ParseCSRPEM(pem.EncodeToMemory(block))
	if csr != nil || err == nil || !strings.HasPrefix(err.Error(), "CSR signature invalid:") {
		t.Fatalf("parse CSR = %v, %v; want no CSR and a signature refusal", csr, err)
	}
}
