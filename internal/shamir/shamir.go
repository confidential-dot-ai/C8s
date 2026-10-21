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
	secret := make([]byte, size)
	for b := range secret {
		// Lagrange interpolation at x = 0.
		var acc byte
		for i, si := range shares {
			num, den := byte(1), byte(1)
			for j, sj := range shares {
				if i == j {
					continue
				}
				num = mul(num, sj.X)
				den = mul(den, si.X^sj.X)
			}
			acc ^= mul(si.Y[b], div(num, den))
		}
		secret[b] = acc
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

var expT, logT = tables()

// tables are GF(2^8) exponent and log tables, generator 3, modulus x^8 +
// x^4 + x^3 + x + 1 (AES).
func tables() (exp [510]byte, log [256]byte) {
	x := byte(1)
	for i := range 255 {
		exp[i] = x
		log[x] = byte(i)
		// x *= 3: x*2 ^ x, reducing by the modulus.
		hi := x & 0x80
		x2 := x << 1
		if hi != 0 {
			x2 ^= 0x1b
		}
		x = x2 ^ x
	}
	for i := 255; i < 510; i++ {
		exp[i] = exp[i-255]
	}
	return exp, log
}

func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expT[int(logT[a])+int(logT[b])]
}

func div(a, b byte) byte {
	if b == 0 {
		panic("shamir: division by zero")
	}
	if a == 0 {
		return 0
	}
	return expT[int(logT[a])+255-int(logT[b])]
}
