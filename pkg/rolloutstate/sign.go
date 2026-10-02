// Package rolloutstate signs and verifies CDS's allowlist rollout state.
//
// The mesh CA key that signs X.509 leaves also signs the state, so every
// signature is domain-separated: it covers SHA-384 of a context string, a
// zero byte, and the exact state bytes. The context names the endpoint the
// state came from, so the key never signs bare JSON and a state signed for
// one endpoint does not verify as the other.
package rolloutstate

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
)

// Signature contexts. They are hash inputs shipped in deployed evidence, so
// they never change; a new format gets a new context.
const (
	// ContextState signs GET /.well-known/c8s/state.
	ContextState = "c8s/rollout-state/v1"
	// ContextChallenge signs POST /.well-known/c8s/state/challenge, whose
	// state carries the caller's nonce.
	ContextChallenge = "c8s/rollout-state-challenge/v1"
)

// Digest returns SHA-384(context || 0x00 || state).
func Digest(context string, state []byte) [48]byte {
	h := sha512.New384()
	h.Write([]byte(context))
	h.Write([]byte{0})
	h.Write(state)
	var sum [48]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// Sign returns an ASN.1 ECDSA signature by key over Digest(context, state).
func Sign(key *ecdsa.PrivateKey, context string, state []byte) ([]byte, error) {
	if context == "" {
		return nil, fmt.Errorf("rolloutstate: empty signature context")
	}
	sum := Digest(context, state)
	return ecdsa.SignASN1(rand.Reader, key, sum[:])
}

// Verify reports whether sig is key's signature over Digest(context, state).
func Verify(key *ecdsa.PublicKey, context string, state, sig []byte) bool {
	if context == "" {
		return false
	}
	sum := Digest(context, state)
	return ecdsa.VerifyASN1(key, sum[:], sig)
}
