package attestation

import (
	"testing"
	"time"
)

func TestR3IssuingReplicaRejectsPreRotationChallenge(t *testing.T) {
	key := []byte("old")
	a, b := NewChallengeStore(time.Minute), NewChallengeStore(time.Minute)
	a.SetSharedKey(func() []byte { return key })
	b.SetSharedKey(func() []byte { return key })
	c := a.Create()
	key = []byte("new")
	if b.Consume(c[:]) {
		t.Fatal("foreign accepted")
	}
	if a.Consume(c[:]) {
		t.Fatal("issuer accepted pre-rotation nonce")
	}
}

func TestR3SharedLocalChallengeExpiryAndKeyLoss(t *testing.T) {
	key := []byte("key")
	s := NewChallengeStore(time.Minute)
	s.SetSharedKey(func() []byte { return key })
	c := s.Create()
	key = nil
	if s.Consume(c[:]) {
		t.Fatal("issuer accepted after key loss")
	}
	key = []byte("new")
	fresh := s.Create()
	if !s.Consume(fresh[:]) || s.Consume(fresh[:]) {
		t.Fatal("fresh challenge must work exactly once")
	}
	// A local map hit cannot override the signed TTL, either.
	expired := signedChallenge(key, time.Now().Add(-time.Second))
	var nonce [32]byte
	copy(nonce[:], expired)
	s.challenges[nonce] = time.Now()
	if s.Consume(expired) {
		t.Fatal("local map hit bypassed signed expiry")
	}
}
