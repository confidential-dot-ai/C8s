// Package shamir splits a secret into n shares, any k of which recover it
// and fewer reveal nothing about it (Shamir's scheme over GF(2^8), one
// polynomial per byte). It is what lets an operator hold the CDS recovery
// key as k-of-n custodians instead of one person, as Vault does with its
// unseal key.
package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Share is one share: its x coordinate (1..255) and one y byte per secret
// byte.
type Share struct {
	X byte
	Y []byte
}

// Split returns n shares of secret, any k of which recover it.
func Split(secret []byte, n, k int) ([]Share, error) {
	switch {
	case len(secret) == 0:
		return nil, errors.New("shamir: empty secret")
	case k < 2 || k > n:
		return nil, fmt.Errorf("shamir: threshold %d must be between 2 and the share count %d", k, n)
	case n > 255:
		return nil, errors.New("shamir: at most 255 shares")
	}
	shares := make([]Share, n)
	for i := range shares {
		shares[i] = Share{X: byte(i + 1), Y: make([]byte, len(secret))}
	}
	coeffs := make([]byte, k)
	for b, s := range secret {
		coeffs[0] = s
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}
		for i := range shares {
			shares[i].Y[b] = eval(coeffs, shares[i].X)
		}
	}
	clear(coeffs)
	return shares, nil
}

// Combine recovers the secret from at least k distinct shares (it cannot
// tell k; callers check the result, as cdsha does against the key's
// fingerprint).
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("shamir: need at least two shares")
	}
	size := len(shares[0].Y)
	seen := map[byte]bool{}
	for _, s := range shares {
		if s.X == 0 || seen[s.X] {
			return nil, errors.New("shamir: shares must have distinct non-zero x")
		}
		if len(s.Y) != size {
			return nil, errors.New("shamir: shares of different lengths")
		}
		seen[s.X] = true
	}
	// Lagrange basis at x = 0; it depends only on the public x coordinates.
	basis := make([]byte, len(shares))
	for i, si := range shares {
		num, den := byte(1), byte(1)
		for j, sj := range shares {
			if i != j {
				num, den = mul(num, sj.X), mul(den, si.X^sj.X)
			}
		}
		basis[i] = mul(num, inv(den))
	}
	secret := make([]byte, size)
	for b := range secret {
		for i, s := range shares {
			secret[b] ^= mul(s.Y[b], basis[i])
		}
	}
	return secret, nil
}

// eval evaluates the polynomial with the given coefficients at x (Horner).
func eval(coeffs []byte, x byte) byte {
	var y byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		y = mul(y, x) ^ coeffs[i]
	}
	return y
}

// mul multiplies in GF(2^8) with the AES modulus, in constant time: no
// branch or table index depends on a secret byte.
func mul(a, b byte) byte {
	var r byte
	for i := 7; i >= 0; i-- {
		r = -(b>>i&1)&a ^ -(r>>7)&0x1b ^ r<<1
	}
	return r
}

// inv is a^254, the inverse of a non-zero a.
func inv(a byte) byte {
	r := byte(1)
	for range 254 {
		r = mul(r, a)
	}
	return r
}
