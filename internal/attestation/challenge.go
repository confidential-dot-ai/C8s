package attestation

import (
	"crypto/rand"
	"sync"
	"time"
)

// ChallengeStore holds short-lived attestation challenges. Each challenge can
// only be consumed once, preventing replay attacks.
//
// NOTE: challenges are stored in-memory and lost on restart. This is acceptable
// for single-instance deployments but must be addressed for HA configurations.
// One TTL governs every challenge, so insertion order is expiry order: issued
// holds the keys oldest-first, and a consumed key stays there until it reaches
// the front.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[[32]byte]time.Time
	issued     [][32]byte
	ttl        time.Duration
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
		return false
	}
	delete(s.challenges, key)

	return time.Since(created) < s.ttl
}
