package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// Capsule is an experimental encrypted copy of one authority's custody
// material. Each independently protected wrapping key gets its own copy.
// Its WAL key also protects the CA material in the encrypted log. It adds no
// election, issuance ledger or storage credentials.
// Possession of a capsule does not establish that its enrollment is current.
// This primitive is NOT wired to production provisioning or an HTTP endpoint.
type Capsule struct {
	Version    int    `json:"version"`
	Ciphertext []byte `json:"ciphertext"`
}

func capsuleCipher(wrappingKey []byte) (cipher.AEAD, error) {
	if len(wrappingKey) != 32 {
		return nil, errors.New("recovery: a 256-bit protected wrapping key is required")
	}
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func capsuleContext(expected Identity, record []byte) ([]byte, error) {
	if err := expected.check(); err != nil {
		return nil, err
	}
	if len(record) == 0 || len(record) > maxRegistrationBytes {
		return nil, errors.New("recovery: existing bounded registration required")
	}
	identity, _ := json.Marshal(expected)
	hash := sha256.Sum256(record)
	context := append([]byte("c8s/cds-recovery/capsule/v1\x00"), identity...)
	return append(context, hash[:]...), nil
}

// SealAuthority encrypts the WAL key and authority signing seed. Call only
// inside the approved custodian: wrappingKey must come from a protected root,
// not an operator-readable file or Kubernetes Secret. Supplying random bytes
// in an ordinary process is useful for protocol tests, not hardware custody.
func SealAuthority(expected Identity, record, key []byte, signer ed25519.PrivateKey, wrappingKey []byte) (Capsule, error) {
	if _, err := checkRegistration(expected, record, key, signer); err != nil {
		return Capsule{}, err
	}
	canonical := ed25519.NewKeyFromSeed(signer[:ed25519.SeedSize])
	defer clear(canonical)
	if !bytes.Equal(canonical, signer) {
		return Capsule{}, errors.New("recovery: inconsistent signing material")
	}
	aad, err := capsuleContext(expected, record)
	if err != nil {
		return Capsule{}, err
	}
	aead, err := capsuleCipher(wrappingKey)
	if err != nil {
		return Capsule{}, err
	}
	material := make([]byte, 64)
	defer clear(material)
	copy(material, key)
	copy(material[32:], signer[:ed25519.SeedSize])
	return Capsule{Version: 1, Ciphertext: aead.Seal(nil, nil, material, aad)}, nil
}

// RestoreSealedAuthority reconstructs a replica of the existing authority from
// encrypted custody material. expected and record are trusted selections, not
// values learned from the capsule. This verifies integrity, not freshness:
// an old intact capsule plus its old registration can still be restored.
// Version retirement needs an independently fresh decision before release.
func RestoreSealedAuthority(parent context.Context, expected Identity, record []byte, capsule Capsule, wrappingKey []byte, verifier string) (*Authority, error) {
	material, err := openCapsule(expected, record, capsule, wrappingKey)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	signer := ed25519.NewKeyFromSeed(material[32:])
	defer clear(signer)
	return NewAuthority(parent, expected, record, material[:32], signer, verifier)
}

func openCapsule(expected Identity, record []byte, capsule Capsule, wrappingKey []byte) ([]byte, error) {
	aad, err := capsuleContext(expected, record)
	if err != nil {
		return nil, err
	}
	aead, err := capsuleCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	if capsule.Version != 1 || len(capsule.Ciphertext) != 64+aead.Overhead() {
		return nil, errors.New("recovery: invalid custody capsule")
	}
	material, err := aead.Open(nil, nil, capsule.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("recovery: capsule binding or authentication failed")
	}
	return material, nil
}
