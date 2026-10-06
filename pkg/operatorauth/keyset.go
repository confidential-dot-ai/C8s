package operatorauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
)

// KeySetDigestSize is the size of a KeySetDigest result.
const KeySetDigestSize = sha256.Size

// keySetDomain separates the operator-key-set digest preimage from any other
// SHA-256 input. Shared by KeySetDigest and KeySetHash so the two are one
// commitment in two encodings.
const keySetDomain = "c8s-operator-key-set-v1\x00"

// KeySetDigest returns the canonical digest of an operator public-key set
// (docs/armtls.md): SHA-256 over keySetDomain followed by the sorted,
// deduplicated SHA-256 fingerprints of each key's PKIX/SPKI DER. Independent of
// PEM formatting, key order, and duplicates, so any faithful copy of the bundle
// digests identically. The empty set is a defined, attestable value ("no keys
// pinned / writes disabled").
//
// KeySetHash is the lowercase-hex form of this digest — the same commitment.
func KeySetDigest(keys []*ecdsa.PublicKey) ([]byte, error) {
	fps := make([][]byte, 0, len(keys))
	for i, pub := range keys {
		if pub == nil {
			return nil, fmt.Errorf("operator key %d is nil", i)
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("marshal operator key %d: %w", i, err)
		}
		fp := sha256.Sum256(der)
		fps = append(fps, fp[:])
	}
	slices.SortFunc(fps, bytes.Compare)

	h := sha256.New()
	h.Write([]byte(keySetDomain))
	var prev []byte
	for _, fp := range fps {
		if bytes.Equal(fp, prev) {
			continue
		}
		h.Write(fp)
		prev = fp
	}
	return h.Sum(nil), nil
}
