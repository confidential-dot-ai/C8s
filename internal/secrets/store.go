// Package secrets holds the CDS secret store and the policy that gates access
// to it. See docs/secrets.md.
package secrets

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// ErrNotFound reports a path the store does not hold.
var ErrNotFound = errors.New("secrets: no such path")

// The two refusals a write that grows the path map can meet.
var (
	ErrHolderQuota = errors.New("secrets: holder path quota")
	ErrStoreFull   = errors.New("secrets: store path ceiling")
)

// Origin records what put a value at a path.
type Origin string

const (
	// OriginWorkload marks a value CDS generated for a workload that found its
	// path empty.
	OriginWorkload Origin = "workload"
	// OriginOperator marks a value an operator supplied over PUT /secrets/*.
	OriginOperator Origin = "operator"
)

// Holder is the party a stored path is charged to. Origin and name together are
// the key, so an allowlist entry named "operator" is a different holder from
// the operator.
type Holder struct {
	origin Origin
	name   string
}

// String names the holder for a log line. It never carries a value.
func (h Holder) String() string {
	if h.origin == OriginOperator {
		return string(OriginOperator)
	}
	return fmt.Sprintf("%s %q", h.origin, h.name)
}

// MarshalText renders the holder as its String form, so a structured log
// carries the name.
func (h Holder) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// WorkloadHolder charges a path to the allowlist entry whose grant authorized
// the write.
func WorkloadHolder(workload string) Holder {
	return Holder{origin: OriginWorkload, name: workload}
}

// OperatorHolder charges a path to the operator; the ceiling is its only bound.
func OperatorHolder() Holder {
	return Holder{origin: OriginOperator}
}

// Held describes what a path already contained when a write arrived. It carries
// the origin and never the value: the operator write path reports what it is
// about to displace, and that report must not turn a write into a read.
type Held struct {
	Exists bool
	Origin Origin
}

// Store is the secret backend.
//
// Generation lives above the store, not inside it: a backing store generates in
// its own way — a KMS wraps a key, a vault mints its own — so a store that also
// chose values would force every backend to reimplement or contradict this
// one's policy. PutIfAbsent is a compare-and-set, which every real key-value
// store offers.
type Store interface {
	Get(ctx context.Context, path string) ([]byte, error)
	// PutIfAbsent stores value at path if nothing is there, returning what the
	// path holds afterwards and what was already there. held.Exists reports that
	// the write did not happen.
	PutIfAbsent(ctx context.Context, path string, value []byte, by Holder) (current []byte, held Held, err error)
	// Put stores value at path, replacing anything already there, and reports
	// what it displaced. The path is charged to OperatorHolder, whose only
	// bound is the ceiling.
	Put(ctx context.Context, path string, value []byte) (Held, error)
	// TopHolders returns the n holders with the most paths, largest first.
	TopHolders(n int) []HolderPaths
}

// GeneratedValueBytes is the size of a value CDS mints for a workload that
// finds its path empty. 32 bytes is a symmetric key's worth of entropy, which
// is what these values are used as.
const GeneratedValueBytes = 32

// Generate returns a fresh secret value.
func Generate() ([]byte, error) {
	b := make([]byte, GeneratedValueBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("secrets: generate value: %w", err)
	}
	return b, nil
}

// DefaultMaxPathsPerHolder is the shipped per-holder path quota.
const DefaultMaxPathsPerHolder = 64

// MemoryStore keeps secrets in the CDS process and nowhere else. They do not
// survive a restart — see docs/secrets.md, "Restarts".
//
// A bound refuses the write: an entry is the only copy of its value.
type MemoryStore struct {
	mu     sync.RWMutex
	values map[string]entry
	// holders counts each holder's paths. Its sum is len(values).
	holders map[Holder]int

	maxPaths     int
	maxPerHolder int
	maxValue     int
}

type entry struct {
	value  []byte
	holder Holder
}

// NewMemoryStore builds the store. maxPaths bounds distinct paths across every
// holder, maxPerHolder bounds one holder's, and maxValue bounds one value.
// Operator writes count against maxPaths only. maxPerHolder must be below
// maxPaths.
func NewMemoryStore(maxPaths, maxPerHolder, maxValue int) *MemoryStore {
	if maxPerHolder >= maxPaths {
		panic(fmt.Sprintf("secrets: maxPerHolder %d must be below maxPaths %d", maxPerHolder, maxPaths))
	}
	return &MemoryStore{
		values:       make(map[string]entry),
		holders:      make(map[Holder]int),
		maxPaths:     maxPaths,
		maxPerHolder: maxPerHolder,
		maxValue:     maxValue,
	}
}

func (s *MemoryStore) Get(_ context.Context, path string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.values[path]
	if !ok {
		return nil, ErrNotFound
	}
	// Copy: the caller must not be able to mutate stored state through the
	// slice it is handed.
	return append([]byte(nil), e.value...), nil
}

func (s *MemoryStore) PutIfAbsent(_ context.Context, path string, value []byte, by Holder) ([]byte, Held, error) {
	if err := s.checkValue(value); err != nil {
		return nil, Held{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.values[path]; ok {
		return append([]byte(nil), e.value...), Held{Exists: true, Origin: e.holder.origin}, nil
	}
	if err := s.checkRoomLocked(by); err != nil {
		return nil, Held{}, err
	}
	s.storeLocked(path, value, by)
	return append([]byte(nil), value...), Held{}, nil
}

func (s *MemoryStore) Put(_ context.Context, path string, value []byte) (Held, error) {
	if err := s.checkValue(value); err != nil {
		return Held{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, existed := s.values[path]
	if !existed {
		if err := s.checkRoomLocked(OperatorHolder()); err != nil {
			return Held{}, err
		}
	}
	s.storeLocked(path, value, OperatorHolder())
	return Held{Exists: existed, Origin: prior.holder.origin}, nil
}

func (s *MemoryStore) checkValue(value []byte) error {
	if len(value) > s.maxValue {
		return fmt.Errorf("secrets: value is %d bytes, limit is %d", len(value), s.maxValue)
	}
	return nil
}

// storeLocked writes the entry and moves the path's charge to by, so replacing
// another holder's value returns that holder's quota.
func (s *MemoryStore) storeLocked(path string, value []byte, by Holder) {
	if prior, ok := s.values[path]; ok {
		if s.holders[prior.holder] <= 1 {
			delete(s.holders, prior.holder)
		} else {
			s.holders[prior.holder]--
		}
	}
	s.values[path] = entry{value: append([]byte(nil), value...), holder: by}
	s.holders[by]++
}

// checkRoomLocked guards the path bounds for a write that grows the map:
// callers hold the lock and have established the path is absent. The holder's
// quota answers before the ceiling.
func (s *MemoryStore) checkRoomLocked(by Holder) error {
	if by.origin != OriginOperator {
		if held := s.holders[by]; held >= s.maxPerHolder {
			return fmt.Errorf("%w: %s %q holds %d paths, limit is %d", ErrHolderQuota, by.origin, by.name, held, s.maxPerHolder)
		}
	}
	if len(s.values) >= s.maxPaths {
		return fmt.Errorf("%w: store holds %d paths, limit is %d", ErrStoreFull, len(s.values), s.maxPaths)
	}
	return nil
}

// Len reports how many paths the store holds, for metrics and tests.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}

// HolderPaths is one holder's share of the store.
type HolderPaths struct {
	Holder Holder `json:"holder"`
	Paths  int    `json:"paths"`
}

// TopHolders returns the n holders with the most paths, largest first, ties
// broken by holder so the order is stable.
func (s *MemoryStore) TopHolders(n int) []HolderPaths {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]HolderPaths, 0, len(s.holders))
	for h, paths := range s.holders {
		out = append(out, HolderPaths{Holder: h, Paths: paths})
	}
	slices.SortFunc(out, func(a, b HolderPaths) int {
		if c := cmp.Compare(b.Paths, a.Paths); c != 0 {
			return c
		}
		return cmp.Or(cmp.Compare(a.Holder.origin, b.Holder.origin), cmp.Compare(a.Holder.name, b.Holder.name))
	})
	return slices.Clip(out[:min(n, len(out))])
}
