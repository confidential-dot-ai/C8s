package attestation

import (
	"encoding/binary"
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

// signedChallenge is a challenge valid under key that expires at expiry.
func signedChallenge(key []byte, expiry time.Time) []byte {
	var c [32]byte
	binary.BigEndian.PutUint64(c[:8], uint64(expiry.UnixNano()))
	copy(c[16:], challengeMAC(key, c[:16]))
	return c[:]
}

// A correctly signed challenge is refused once expired, and also when it
// claims to live longer than the TTL (clock skew, or minted under a leaked
// key with a long life).
func TestSharedChallengeExpiryBounds(t *testing.T) {
	key := []byte("k")
	s := NewChallengeStore(time.Minute)
	s.SetSharedKey(func() []byte { return key })
	now := time.Now()
	for name, c := range map[string]struct {
		expiry time.Time
		ok     bool
	}{
		"live":           {now.Add(30 * time.Second), true},
		"expired":        {now.Add(-time.Second), false},
		"beyond the TTL": {now.Add(2 * time.Minute), false},
	} {
		if got := s.Consume(signedChallenge(key, c.expiry)); got != c.ok {
			t.Errorf("%s: accepted = %v, want %v", name, got, c.ok)
		}
	}
}
