package attestation

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/cache"
)

// ChallengeStore holds short-lived attestation challenges. Each challenge can
// only be consumed once, preventing replay attacks.
//
// Challenges are stored in memory and lost on restart; HA replicas share
// them through SetSharedKey. One TTL governs every challenge, so insertion
// order is expiry order: issued holds the keys oldest-first, and a consumed key
// stays there until it reaches the front.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[[32]byte]time.Time
	issued     [][32]byte
	ttl        time.Duration

	// sharedKey, when set (HA CDS), makes challenges self-verifying, so a
	// challenge issued by one replica is accepted by another holding the
	// same key. It returns nil while no key is available.
	sharedKey func() []byte
	// redeemed holds self-verifying challenges this replica accepted, for
	// single use here; another replica may accept the same one once.
	redeemed *cache.Expiring
}

// SetSharedKey switches the store to self-verifying challenges: expiry (8
// bytes), random (8 bytes) and a 16-byte HMAC-SHA256 under key(), 32 bytes in
// all, the size clients already send back. Call before serving.
func (s *ChallengeStore) SetSharedKey(key func() []byte) {
	s.sharedKey = key
	s.redeemed = cache.NewExpiring()
}

func challengeMAC(key []byte, head []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("c8s-challenge-v1\x00"))
	mac.Write(head)
	return mac.Sum(nil)[:16]
}

// NewChallengeStore creates a new challenge store with the given TTL.
func NewChallengeStore(ttl time.Duration) ChallengeStore {
	return ChallengeStore{
		challenges: make(map[[32]byte]time.Time),
		ttl:        ttl,
	}
}

// maxChallenges bounds the challenges a store holds at roughly 15 MiB. The
// queue that orders them is compacted at twice that, since a key Consume
// removed is only reclaimed when it reaches the front or a compaction passes
// it.
const maxChallenges = 1 << 17

// Create generates a new 32-byte random challenge and stores it.
func (s *ChallengeStore) Create() [32]byte {
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	if s.sharedKey != nil {
		if key := s.sharedKey(); key != nil {
			binary.BigEndian.PutUint64(challenge[:8], uint64(time.Now().Add(s.ttl).UnixNano()))
			copy(challenge[16:], challengeMAC(key, challenge[:16]))
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.dropExpired(now)
	if len(s.issued) >= 2*maxChallenges {
		s.compact(now)
	}
	if len(s.challenges) >= maxChallenges {
		s.dropOldest()
	}

	s.challenges[challenge] = now
	s.issued = append(s.issued, challenge)
	return challenge
}

// dropExpired removes challenges from the front of issued until it reaches one
// that is both live and unconsumed.
func (s *ChallengeStore) dropExpired(now time.Time) {
	for len(s.issued) > 0 {
		front := s.issued[0]
		created, live := s.challenges[front]
		if live && now.Sub(created) < s.ttl {
			return
		}
		delete(s.challenges, front)
		s.issued = s.issued[1:]
	}
}

// compact rebuilds issued from the challenges still live, in order, so the
// keys Consume removed from the middle stop occupying it. It runs once per
// maxChallenges mints at most, since it leaves issued no longer than the map.
func (s *ChallengeStore) compact(now time.Time) {
	kept := s.issued[:0]
	for _, key := range s.issued {
		created, live := s.challenges[key]
		if !live {
			continue
		}
		if now.Sub(created) >= s.ttl {
			delete(s.challenges, key)
			continue
		}
		kept = append(kept, key)
	}
	s.issued = kept
}

// dropOldest makes room for one challenge by removing the oldest live one.
func (s *ChallengeStore) dropOldest() {
	if len(s.issued) == 0 {
		return
	}
	delete(s.challenges, s.issued[0])
	s.issued = s.issued[1:]
}

// Consume removes and validates a challenge, returning true if it was valid
// and not expired. The challenge is removed regardless so it cannot be reused.
func (s *ChallengeStore) Consume(challenge []byte) bool {
	if len(challenge) != 32 {
		return false
	}

	var key [32]byte
	copy(key[:], challenge)

	s.mu.Lock()
	defer s.mu.Unlock()

	created, ok := s.challenges[key]
	if !ok {
		return s.consumeShared(key)
	}
	delete(s.challenges, key)
	if s.redeemed != nil {
		// A self-verifying challenge stays valid by MAC: mark it used here too.
		s.redeemed.Set(key, nil, s.ttl)
	}

	return time.Since(created) < s.ttl
}

// consumeShared accepts a self-verifying challenge another replica issued:
// MAC under the current shared key, not expired, not yet redeemed here.
// Caller holds s.mu.
func (s *ChallengeStore) consumeShared(c [32]byte) bool {
	if s.sharedKey == nil {
		return false
	}
	key := s.sharedKey()
	if key == nil || !hmac.Equal(c[16:], challengeMAC(key, c[:16])) {
		return false
	}
	now := time.Now()
	expiry := time.Unix(0, int64(binary.BigEndian.Uint64(c[:8])))
	if !now.Before(expiry) || expiry.Sub(now) > s.ttl {
		return false
	}
	if _, used := s.redeemed.Get(c); used {
		return false
	}
	s.redeemed.Set(c, nil, expiry.Sub(now)) // also drops expired entries
	if s.redeemed.Len() > maxChallenges {
		s.redeemed.Delete(c)
		return false
	}
	return true
}
