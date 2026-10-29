package attestation

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// Challenges mints and redeems the short-lived nonces that make an
// attestation request fresh. Each replica redeems a given nonce once.
type Challenges interface {
	Create() ([challengeBytes]byte, error)
	Consume(challenge []byte) bool
}

const challengeBytes = 32

// maxChallenges bounds the challenges a LocalChallenges store holds, at
// roughly 15 MiB of keys and timestamps.
const maxChallenges = 1 << 17

func challengeOf(b []byte) ([challengeBytes]byte, bool) {
	var challenge [challengeBytes]byte
	if len(b) != len(challenge) {
		return challenge, false
	}
	copy(challenge[:], b)
	return challenge, true
}

func randomChallenge() ([challengeBytes]byte, error) {
	var challenge [challengeBytes]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return challenge, fmt.Errorf("attestation: read random: %w", err)
	}
	return challenge, nil
}

// LocalChallenges is the challenge store of a single CDS: a nonce it mints is
// redeemable here alone, and nowhere after a restart.
//
// One TTL governs every challenge, so insertion order is expiry order: issued
// holds the keys oldest-first, and a consumed key stays there until it reaches
// the front.
type LocalChallenges struct {
	mu         sync.Mutex
	challenges map[[challengeBytes]byte]time.Time
	issued     [][challengeBytes]byte
	ttl        time.Duration
}

// NewLocalChallenges builds the store; ttl bounds how long a nonce stays redeemable.
func NewLocalChallenges(ttl time.Duration) *LocalChallenges {
	return &LocalChallenges{
		challenges: make(map[[challengeBytes]byte]time.Time),
		ttl:        ttl,
	}
}

func (s *LocalChallenges) Create() ([challengeBytes]byte, error) {
	challenge, err := randomChallenge()
	if err != nil {
		return challenge, err
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
	return challenge, nil
}

// dropExpired removes challenges from the front of issued until it reaches one
// that is both live and unconsumed.
func (s *LocalChallenges) dropExpired(now time.Time) {
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
func (s *LocalChallenges) compact(now time.Time) {
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
func (s *LocalChallenges) dropOldest() {
	if len(s.issued) == 0 {
		return
	}
	delete(s.challenges, s.issued[0])
	s.issued = s.issued[1:]
}

// Consume removes the challenge and reports that it was live. It is removed
// either way, so it cannot be redeemed twice.
func (s *LocalChallenges) Consume(challenge []byte) bool {
	key, ok := challengeOf(challenge)
	if !ok {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	created, held := s.challenges[key]
	delete(s.challenges, key)
	if !held {
		return false
	}
	return time.Since(created) < s.ttl
}
