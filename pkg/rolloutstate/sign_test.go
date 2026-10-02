package rolloutstate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"testing"
)

func TestSignIsDomainSeparated(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"protocol":1}`)
	sig, err := Sign(key, ContextState, state)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(&key.PublicKey, ContextState, state, sig) {
		t.Fatal("signature does not verify under its own context")
	}
	if Verify(&key.PublicKey, ContextChallenge, state, sig) {
		t.Fatal("a state signature verifies as a challenge signature")
	}
	if Verify(&key.PublicKey, "", state, sig) {
		t.Fatal("verified with an empty context")
	}
	bare := sha512.Sum384(state)
	if ecdsa.VerifyASN1(&key.PublicKey, bare[:], sig) {
		t.Fatal("signature verifies over the bare state bytes")
	}
	if _, err := Sign(key, "", state); err == nil {
		t.Fatal("signed with an empty context")
	}
	// The zero byte keeps a context and a state from sliding into each other.
	if Digest("ab", []byte("c")) == Digest("a", []byte("bc")) {
		t.Fatal("context and state are not framed")
	}
}
