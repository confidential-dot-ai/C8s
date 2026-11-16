package attestation

import (
	"encoding/binary"
	"testing"
	"time"
)

// testPool is a shared pool with a key the test rotates and a clock it moves.
func testPool(t *testing.T, purpose string, key *[]byte, clock *time.Time) *SharedChallenges {
	t.Helper()
	s := NewSharedChallenges(purpose, time.Minute, func() []byte { return *key })
	s.now = func() time.Time { return *clock }
	return s
}

var signedSeq uint64

// signedChallenge is a distinct challenge valid for purpose under key.
func signedChallenge(key []byte, purpose string, expiry time.Time) []byte {
	signedSeq++
	var n nonce
	n.setExpiry(expiry)
	binary.BigEndian.PutUint64(n.random(), signedSeq)
	mac := challengeMAC(key, purpose, n.signed())
	copy(n.mac(), mac[:])
	return n[:]
}

// A challenge one replica mints is redeemable at another, once per replica.
func TestSharedChallengesCrossReplicas(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	key := []byte("mesh-ca-derived-key")
	rotated := []byte("rotated")
	a := testPool(t, "issuance", &key, &clock)
	b := testPool(t, "issuance", &key, &clock)
	other := testPool(t, "issuance", &rotated, &clock)

	c := mustCreate(t, a)
	if !b.Consume(c[:]) {
		t.Fatal("replica B refused a challenge replica A minted")
	}
	if b.Consume(c[:]) {
		t.Fatal("replica B redeemed the same challenge twice")
	}
	if !a.Consume(c[:]) || a.Consume(c[:]) {
		t.Fatal("the minting replica must redeem its own challenge exactly once")
	}
	if c2 := mustCreate(t, a); other.Consume(c2[:]) {
		t.Fatal("challenge redeemed under another key")
	}
}

// The two pools of one replica share the cluster's key and redeem nothing of
// each other's.
func TestSharedChallengePoolsAreSeparateUnderOneKey(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	key := []byte("mesh-ca-derived-key")
	issuance := testPool(t, "issuance", &key, &clock)
	secrets := testPool(t, "secrets", &key, &clock)

	minted := mustCreate(t, issuance)
	if secrets.Consume(minted[:]) {
		t.Fatal("the secrets pool redeemed an issuance challenge")
	}
	forSecrets := mustCreate(t, secrets)
	if issuance.Consume(forSecrets[:]) {
		t.Fatal("the issuance pool redeemed a secrets challenge")
	}
}

// Only the MAC can tell a tampered expiry from a minted one.
func TestSharedChallengeRefusesTampering(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	key := []byte("k")
	a := testPool(t, "issuance", &key, &clock)
	b := testPool(t, "issuance", &key, &clock)

	tampered := mustCreate(t, a)
	tampered[nonceExpiryBytes-1] ^= 1
	if b.Consume(tampered[:]) {
		t.Fatal("tampered challenge redeemed")
	}
}

// A signed challenge is refused once expired, or when it claims to live
// longer than this pool mints for, clock skew allowed for.
func TestSharedChallengeExpiryBounds(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	key := []byte("k")
	s := testPool(t, "issuance", &key, &clock)

	for name, c := range map[string]struct {
		expiry time.Time
		ok     bool
	}{
		"live": {
			expiry: clock.Add(30 * time.Second),
			ok:     true,
		},
		"expired": {expiry: clock.Add(-time.Second)},
		"inside the skew": {
			expiry: clock.Add(time.Minute + 20*time.Second),
			ok:     true,
		},
		"beyond the skew": {expiry: clock.Add(2 * time.Minute)},
	} {
		if got := s.Consume(signedChallenge(key, "issuance", c.expiry)); got != c.ok {
			t.Errorf("%s: redeemed = %v, want %v", name, got, c.ok)
		}
	}
}

// A replica with no current key mints nothing: the nonce would be redeemable
// nowhere.
func TestSharedChallengeCreateNeedsAKey(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	var none []byte
	s := testPool(t, "issuance", &none, &clock)

	if _, err := s.Create(); err != ErrNoChallengeKey {
		t.Fatalf("Create with no key = %v, want %v", err, ErrNoChallengeKey)
	}
	if s.Consume(signedChallenge([]byte("k"), "issuance", clock.Add(time.Second))) {
		t.Fatal("a replica with no key redeemed a challenge")
	}
}

// A zero-length key is no key: it must not sign anything.
func TestSharedChallengeRefusesAnEmptyKey(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	empty := []byte{}
	s := testPool(t, "issuance", &empty, &clock)

	if _, err := s.Create(); err != ErrNoChallengeKey {
		t.Fatalf("Create with an empty key = %v, want %v", err, ErrNoChallengeKey)
	}
}

// A rotation retires the nonces minted before it, at the minting replica too.
func TestSharedChallengeFollowsTheKey(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	key := []byte("old")
	a := testPool(t, "issuance", &key, &clock)
	b := testPool(t, "issuance", &key, &clock)

	before := mustCreate(t, a)
	key = nil
	if a.Consume(before[:]) || b.Consume(before[:]) {
		t.Fatal("a challenge was redeemed after the key was lost")
	}
	key = []byte("new")
	if a.Consume(before[:]) {
		t.Fatal("a pre-rotation challenge was redeemed under the new key")
	}
	after := mustCreate(t, a)
	if !b.Consume(after[:]) {
		t.Fatal("a challenge minted under the new key was refused")
	}
}

// Two nonces of the same expiry are distinct.
func TestSharedChallengesAreDistinct(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	key := []byte("k")
	s := testPool(t, "issuance", &key, &clock)

	first := mustCreate(t, s)
	second := mustCreate(t, s)
	if first == second {
		t.Fatal("two mints produced the same nonce")
	}
	if !s.Consume(first[:]) || !s.Consume(second[:]) {
		t.Fatal("redeeming one challenge spent the other")
	}
}

// The redeemed nonces a replica remembers are bounded per window, and the
// bound denies redemption; a window turning clears it.
func TestRedeemedChallengesAreBoundedPerWindow(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	key := []byte("k")
	s := testPool(t, "issuance", &key, &clock)
	s.redeemed = newRedeemedSet(s.ttl+clockSkew, 2)
	live := func() []byte { return signedChallenge(key, "issuance", clock.Add(30*time.Second)) }

	first := live()
	second := live()
	third := live()
	if !s.Consume(first) || !s.Consume(second) {
		t.Fatal("a challenge inside the bound was refused")
	}
	if s.Consume(third) {
		t.Fatal("a challenge was redeemed past the bound")
	}
	if s.Consume(first) {
		t.Fatal("a redeemed challenge was redeemed again")
	}

	clock = clock.Add(s.ttl + clockSkew)
	if !s.Consume(live()) {
		t.Fatal("the window did not turn, so the bound never clears")
	}
	if got := s.redeemed.size(); got != 3 {
		t.Fatalf("the replica remembers %d nonces across two windows, want 3", got)
	}
}

// A nonce is an expiry, randomness, and a MAC that fills the rest.
func TestNonceLayoutFillsAChallenge(t *testing.T) {
	var n nonce
	if len(n) != challengeBytes {
		t.Fatalf("a nonce is %d bytes, want %d", len(n), challengeBytes)
	}
	if got := len(n.signed()) + len(n.mac()); got != challengeBytes {
		t.Fatalf("the signed part and the MAC cover %d bytes, want %d", got, challengeBytes)
	}
	if len(n.random()) != nonceRandomBytes {
		t.Fatalf("the randomness is %d bytes, want %d", len(n.random()), nonceRandomBytes)
	}
	at := time.Unix(1_700_000_000, 123)
	n.setExpiry(at)
	if !n.expiry().Equal(at) {
		t.Fatalf("expiry read back as %v, want %v", n.expiry(), at)
	}
	if binary.BigEndian.Uint64(n[:nonceExpiryBytes]) != uint64(at.UnixNano()) {
		t.Fatal("the expiry is not the first field of the nonce")
	}
}
