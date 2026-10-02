package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// HandleAuthenticate returns a handler that issues a single-use base64
// challenge nonce.
func HandleAuthenticate(challenges *ChallengeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		challenge := challenges.Create()
		encoded := base64.StdEncoding.EncodeToString(challenge[:])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: encoded})
	}
}

// ParseAndVerifyCSR decodes a PEM CSR and verifies its self-signature.
func ParseAndVerifyCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR must be a PEM-encoded certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	return csr, nil
}

// ECDSAPublicKeyFromCSR returns the CSR's ECDSA public key or an error if
// the key is not ECDSA.
func ECDSAPublicKeyFromCSR(csr *x509.CertificateRequest) (*ecdsa.PublicKey, error) {
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CSR public key must be ECDSA, got %T", csr.PublicKey)
	}
	return pub, nil
}

// WriteError writes a JSON error response in the C8s error-envelope shape.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(types.ErrorResponse{
		Error:   code,
		Message: message,
	})
}

// ReadinessFunc is a function that returns whether the service is ready.
type ReadinessFunc func() bool

// HandleReadyz handles GET /readyz.
func HandleReadyz(readyFn ReadinessFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if readyFn() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}
}
