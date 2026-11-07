package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

// ECDSAPublicKeyFromCSR returns the CSR's ECDSA public key or an error if
// the key is not ECDSA.
func ECDSAPublicKeyFromCSR(csr *x509.CertificateRequest) (*ecdsa.PublicKey, error) {
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CSR public key must be ECDSA, got %T", csr.PublicKey)
	}
	return pub, nil
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
