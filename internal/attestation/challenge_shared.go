package attestation

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrNoChallengeKey reports a CDS HA replica holding no current cluster key.
// It clears once the replica serves, so it is retryable.
var ErrNoChallengeKey = errors.New("attestation: no challenge key; this CDS is not serving yet; retry")

// ClusterKey returns the cluster's current challenge key, or nothing while
// this replica may not serve. It is called concurrently and must not hand
// back a slice it later writes to.
type ClusterKey func() []byte

// clockSkew is how far a replica's clock may trail the one that minted a
// nonce and still redeem it.
const clockSkew = 30 * time.Second

// maxRedeemed bounds the nonces one replica remembers redeeming inside a
// window. The set holds two windows, so twice that many 32-byte keys at most,
// roughly 12 MiB.
const maxRedeemed = 1 << 17

// The layout of a self-verifying nonce: the expiry and the randomness the MAC
// covers, then the MAC.
const (
	nonceExpiryBytes = 8
	nonceRandomBytes = 8
	nonceSignedBytes = nonceExpiryBytes + nonceRandomBytes
	nonceMACBytes    = challengeBytes - nonceSignedBytes
)

// nonce is a challenge any replica of the cluster can check: the MAC covers
// the expiry and the randomness in front of it, so neither can be changed
// without the cluster's key.
type nonce [challengeBytes]byte

func (n *nonce) signed() []byte {
	return n[:nonceSignedBytes]
}

func (n *nonce) mac() []byte {
	return n[nonceSignedBytes:]
}

func (n *nonce) random() []byte {
	return n[nonceExpiryBytes:nonceSignedBytes]
}

func (n *nonce) expiry() time.Time {
	return time.Unix(0, int64(binary.BigEndian.Uint64(n[:nonceExpiryBytes])))
}

func (n *nonce) setExpiry(at time.Time) {
	binary.BigEndian.PutUint64(n[:nonceExpiryBytes], uint64(at.UnixNano()))
}

// challengeMAC binds a nonce to the cluster's key and to its pool, so a nonce
// one pool minted verifies in no other.
func challengeMAC(key []byte, purpose string, signed []byte) [nonceMACBytes]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("c8s-challenge-v1\x00"))
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write(signed)
	return [nonceMACBytes]byte(mac.Sum(nil)[:nonceMACBytes])
}

// SharedChallenges is the challenge store of a CDS HA replica: a nonce is
// self-verifying, so the replica that redeems it need not be the one that
// minted it. Each replica redeems a given nonce once.
type SharedChallenges struct {
	// purpose names the pool and is part of what the MAC covers: the pool
	// gating certificate issuance and the one gating secrets redeem nothing of
	// each other's.
	purpose string
	ttl     time.Duration
	key     ClusterKey
	now     func() time.Time
	// redeemed holds the nonces this replica accepted, for single use here.
	redeemed *redeemedSet
}

// NewSharedChallenges builds the pool purpose names; ttl bounds how long a
// nonce any replica minted stays redeemable.
func NewSharedChallenges(purpose string, ttl time.Duration, key ClusterKey) *SharedChallenges {
	return &SharedChallenges{
		purpose:  purpose,
		ttl:      ttl,
		key:      key,
		now:      time.Now,
		redeemed: newRedeemedSet(ttl+clockSkew, maxRedeemed),
	}
}

// Create mints a self-verifying challenge, or reports that this replica holds
// no key to sign one with.
func (s *SharedChallenges) Create() ([challengeBytes]byte, error) {
	key := s.key()
	if len(key) == 0 {
		return [challengeBytes]byte{}, ErrNoChallengeKey
	}
	var n nonce
	if _, err := rand.Read(n.random()); err != nil {
		return [challengeBytes]byte(n), fmt.Errorf("attestation: read random: %w", err)
	}
	n.setExpiry(s.now().Add(s.ttl))
	mac := challengeMAC(key, s.purpose, n.signed())
	copy(n.mac(), mac[:])
	return [challengeBytes]byte(n), nil
}

// Consume accepts a challenge any replica of the cluster minted: signed under
// the current key for this pool, unexpired, and not already redeemed here.
func (s *SharedChallenges) Consume(challenge []byte) bool {
	key, ok := challengeOf(challenge)
	if !ok {
		return false
	}
	n := nonce(key)
	if !s.signedByTheCluster(&n) {
		return false
	}
	now := s.now()
	if !s.redeemable(n.expiry(), now) {
		return false
	}
	return s.redeemed.add(n, now)
}

// signedByTheCluster reports a nonce carrying the MAC of the cluster's
// current key for this pool. A replica with no key accepts none.
func (s *SharedChallenges) signedByTheCluster(n *nonce) bool {
	key := s.key()
	if len(key) == 0 {
		return false
	}
	want := challengeMAC(key, s.purpose, n.signed())
	return hmac.Equal(n.mac(), want[:])
}

// redeemable reports an expiry still ahead of now and no further ahead than
// this pool would have minted it, clock skew allowed for.
func (s *SharedChallenges) redeemable(expiry, now time.Time) bool {
	return now.Before(expiry) && expiry.Sub(now) <= s.ttl+clockSkew
}

// redeemedSet remembers the nonces one replica accepted. It holds the current
// window and the one before it and drops the older whole, so a nonce is
// remembered for at least a window, the longest one can live.
type redeemedSet struct {
	mu       sync.Mutex
	window   time.Duration
	max      int
	since    time.Time
	current  map[nonce]struct{}
	previous map[nonce]struct{}
}

func newRedeemedSet(window time.Duration, max int) *redeemedSet {
	return &redeemedSet{
		window:  window,
		max:     max,
		current: make(map[nonce]struct{}),
	}
}

// add records n as redeemed here, reporting that it was not already and that
// the set had room. A nonce refused at the ceiling is recorded nowhere.
func (r *redeemedSet) add(n nonce, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.turnWindow(now)
	if r.holds(n) {
		return false
	}
	if len(r.current) >= r.max {
		return false
	}
	r.current[n] = struct{}{}
	return true
}

// holds reports a nonce either window remembers (r.mu held).
func (r *redeemedSet) holds(n nonce) bool {
	if _, redeemed := r.current[n]; redeemed {
		return true
	}
	_, redeemed := r.previous[n]
	return redeemed
}

// turnWindow drops the older of the two windows once a whole one has passed
// (r.mu held).
func (r *redeemedSet) turnWindow(now time.Time) {
	if now.Sub(r.since) < r.window {
		return
	}
	r.since = now
	r.previous = r.current
	r.current = make(map[nonce]struct{})
}

// size is how many redeemed nonces the replica remembers, for tests.
func (r *redeemedSet) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.current) + len(r.previous)
}
