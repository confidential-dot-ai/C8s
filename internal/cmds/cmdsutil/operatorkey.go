package cmdsutil

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// LoadOperatorKey reads the key an operator signs with: the private half of
// the pair 'c8s keys new' writes, whose public half the cluster pins. Handing
// it the public half is the mistake the error names.
func LoadOperatorKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := certutil.ParseECPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("must be the private key file, as 'c8s keys new --out' writes it: %w", err)
	}
	return key, nil
}
