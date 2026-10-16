package cdsha

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// State is what a replica holds: the accepted chain and the private key for
// its tail. A zero State is a replica that has not joined yet (L1).
type State struct {
	Chain Chain
	Key   *ecdsa.PrivateKey
}

// Joined reports whether the replica holds a chain and its key (L3).
func (s State) Joined() bool { return len(s.Chain) > 0 && s.Key != nil }

// Outcome of an acceptance decision.
type Outcome int

// Outcomes of Next.
const (
	Extended Outcome = iota + 1 // offer extends the local chain
	Adopted                     // cold start: first chain accepted
)

// ErrNotNewer is returned for an offer whose tuple does not exceed ours (E1, E5).
var ErrNotNewer = errors.New("offer is not newer than local state")

// ErrFork is returned for a newer chain that does not extend ours. A joined
// replica never drops its history (Q1 interim): a fork costs availability,
// never a key takeover. Recovery is restarting the replicas on one branch.
var ErrFork = errors.New("offer forks from local history")

// Next decides whether a replica in cur may move to the offered state.
// INVARIANT: the result always holds a key matching its tail root_cert, so a
// replica can never accept an epoch it cannot serve (L3).
func Next(cur, offer State, clusterID string) (State, Outcome, error) {
	if err := offer.Chain.Verify(clusterID); err != nil {
		return cur, 0, fmt.Errorf("verify offered chain: %w", err)
	}
	key, err := keyFor(offer.Chain.Tail(), offer.Key, cur.Key)
	if err != nil {
		return cur, 0, err
	}
	next := State{Chain: offer.Chain, Key: key}
	if len(cur.Chain) == 0 {
		return next, Adopted, nil
	}
	if !cur.Chain.Tuple().Less(offer.Chain.Tuple()) {
		return cur, 0, ErrNotNewer
	}
	if !offer.Chain.HasPrefix(cur.Chain) {
		return cur, 0, ErrFork
	}
	return next, Extended, nil
}

// keyFor picks the key that matches tail: the offered one, else the one we
// already hold (an UpdateMeasurements epoch keeps the key, D7).
func keyFor(tail Record, offered, held *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	pub, _, err := tail.RootPublicKey()
	if err != nil {
		return nil, err
	}
	for _, k := range []*ecdsa.PrivateKey{offered, held} {
		if k != nil && k.PublicKey.Equal(pub) {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no key for epoch %d root_cert", tail.Epoch)
}
