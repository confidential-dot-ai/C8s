package cdsconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
)

// KMS is the key management service CDS brokers pod secret release to
// (docs/pod-secrets.md). CDS authenticates it by the SHA-256 of its TLS
// certificate's SubjectPublicKeyInfo, not by a CA.
type KMS struct {
	URL    string
	TLSKey [sha256.Size]byte
}

type kmsWire struct {
	URL          string `yaml:"url"`
	TLSKeySHA256 string `yaml:"tlsKeySHA256"`
}

func (w *kmsWire) parse() (*KMS, error) {
	if w == nil {
		return nil, nil
	}
	return ParseKMS(w.URL, w.TLSKeySHA256)
}

// ParseKMS reads a KMS endpoint and the lowercase hex SHA-256 of its TLS key.
func ParseKMS(rawURL, tlsKeySHA256 string) (*KMS, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("kms.url must be an https URL with a host and no credentials, query or fragment")
	}
	pin, err := hex.DecodeString(tlsKeySHA256)
	if err != nil || len(pin) != sha256.Size || hex.EncodeToString(pin) != tlsKeySHA256 {
		return nil, fmt.Errorf("kms.tlsKeySHA256 must be 64 lowercase hex characters")
	}
	k := &KMS{URL: rawURL}
	copy(k.TLSKey[:], pin)
	return k, nil
}

func (k *KMS) wire() *kmsWire {
	if k == nil {
		return nil
	}
	return &kmsWire{URL: k.URL, TLSKeySHA256: hex.EncodeToString(k.TLSKey[:])}
}
