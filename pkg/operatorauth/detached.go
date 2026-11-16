package operatorauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// SignDetached signs sha256(data) with key: ASN.1 DER, base64-encoded. It
// signs the operator-signed objects a cluster carries rather than requests
// (internal/cdsdecree) — a smaller counterpart to the JWT-based Authorization
// scheme this package otherwise implements, over whole bytes rather than one
// request.
func SignDetached(key *ecdsa.PrivateKey, data []byte) (string, error) {
	digest := sha256.Sum256(data)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// VerifyDetached checks line (SignDetached's output, one base64 ASN.1 DER
// signature, optionally with surrounding whitespace) against sha256(data)
// under any one of keys — the same "try each pinned key" shape
// Verifier.Authorize uses for the JWT path.
func VerifyDetached(keys []*ecdsa.PublicKey, data []byte, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return fmt.Errorf("empty signature")
	}
	der, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return fmt.Errorf("not valid base64: %w", err)
	}
	digest := sha256.Sum256(data)
	for _, pub := range keys {
		if ecdsa.VerifyASN1(pub, digest[:], der) {
			return nil
		}
	}
	return fmt.Errorf("does not verify under any pinned key")
}
