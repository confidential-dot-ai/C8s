package attestation

import (
	"testing"
	"time"
)

// TestSharedChallengesAcrossReplicas: with one shared key, a challenge
// issued by replica A is accepted by replica B once, and by A once; a
// different key (another cluster, or after a rotation) rejects it.
func TestSharedChallengesAcrossReplicas(t *testing.T) {
	key := []byte("mesh-ca-derived-key")
	a, b, other := NewChallengeStore(time.Minute), NewChallengeStore(time.Minute), NewChallengeStore(time.Minute)
	a.SetSharedKey(func() []byte { return key })
	b.SetSharedKey(func() []byte { return key })
	other.SetSharedKey(func() []byte { return []byte("rotated") })

	c := a.Create()
	if !b.Consume(c[:]) {
		t.Fatal("replica B refused a challenge replica A issued")
	}
	if b.Consume(c[:]) {
		t.Fatal("replica B accepted the same challenge twice")
	}
	if !a.Consume(c[:]) || a.Consume(c[:]) {
		t.Fatal("issuing replica must accept its own challenge exactly once")
	}
	if c2 := a.Create(); other.Consume(c2[:]) {
		t.Fatal("challenge accepted under another key")
	}
	tampered := a.Create()
	tampered[0] ^= 0x80 // move the expiry
	if b.Consume(tampered[:]) {
		t.Fatal("tampered challenge accepted")
	}
	// Without a key (replica not serving), only local challenges work.
	nokey := NewChallengeStore(time.Minute)
	nokey.SetSharedKey(func() []byte { return nil })
	if c3 := a.Create(); nokey.Consume(c3[:]) {
		t.Fatal("keyless replica accepted a foreign challenge")
	}
	local := nokey.Create()
	if !nokey.Consume(local[:]) {
		t.Fatal("keyless replica refused its own challenge")
	}
}

func TestSharedChallengeExpires(t *testing.T) {
	key := []byte("k")
	a, b := NewChallengeStore(20*time.Millisecond), NewChallengeStore(20*time.Millisecond)
	a.SetSharedKey(func() []byte { return key })
	b.SetSharedKey(func() []byte { return key })
	c := a.Create()
	time.Sleep(40 * time.Millisecond)
	if b.Consume(c[:]) {
		t.Fatal("expired shared challenge accepted")
	}
}
