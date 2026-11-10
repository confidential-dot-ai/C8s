package objectstate

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher binds a complete state to its cluster and storage authority. It
// authenticates contents; the store, independently, must supply freshness.
type Cipher struct {
	aead   cipher.AEAD
	domain []byte
	max    int
}

func NewCipher(
	key []byte,
	domain []byte,
	maxBytes int,
) (*Cipher, error) {
	if len(key) != 32 || len(domain) == 0 || maxBytes <= 64 {
		return nil, errors.New("object state: invalid encryption configuration")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		aead:   aead,
		domain: bytes.Clone(domain),
		max:    maxBytes,
	}, nil
}

func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) > c.max-c.aead.NonceSize()-c.aead.Overhead()-1 {
		return nil, ErrTooLarge
	}
	// A durable key serves independent writers, including abandoned CAS
	// attempts. XChaCha's 192-bit nonce avoids a shared nonce counter.
	nonce := make(
		[]byte,
		c.aead.NonceSize(),
	)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(
		append(
			[]byte{1},
			nonce...,
		),
		nonce,
		plaintext,
		c.domain,
	), nil
}

func (c *Cipher) Open(sealed []byte) ([]byte, error) {
	if len(sealed) > c.max {
		return nil, ErrTooLarge
	}
	if len(sealed) < 1+c.aead.NonceSize()+c.aead.Overhead() || sealed[0] != 1 {
		return nil, errors.New("object state: unsupported encrypted state")
	}
	plain, err := c.aead.Open(
		nil,
		sealed[1:1+c.aead.NonceSize()],
		sealed[1+c.aead.NonceSize():],
		c.domain,
	)
	if err != nil {
		return nil, errors.New("object state: state authentication failed")
	}
	return plain, nil
}
