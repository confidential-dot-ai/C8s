package operatorauth

import "crypto/ecdsa"

// KeyBundle is one operator key set in the two forms a CDS needs: the keys
// that verify operator tokens, and the PEM bytes they were parsed from, which
// CDS serves on PublishedKeysPath. Parsing is the only way to fill one, so the
// two can never name different key sets. The zero value pins no key, which
// disables operator writes.
type KeyBundle struct {
	pem  []byte
	keys []*ecdsa.PublicKey
}

// ParseKeyBundle parses a PEM operator public-key bundle. It fails when the
// bundle holds no EC public key, so a wrong file cannot silently disable
// writes.
func ParseKeyBundle(pemBytes []byte) (KeyBundle, error) {
	keys, err := ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return KeyBundle{}, err
	}
	return KeyBundle{
		pem:  pemBytes,
		keys: keys,
	}, nil
}

func (b KeyBundle) Keys() []*ecdsa.PublicKey {
	return b.keys
}

// PEM is the bundle exactly as parsed, which CDS serves on PublishedKeysPath.
func (b KeyBundle) PEM() []byte {
	return b.pem
}
