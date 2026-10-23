package secrets

import (
	"context"
	"errors"
	"fmt"
)

// Replicator carries a secret write to every CDS replica (CDS HA) and returns
// the result this replica's Apply produced once it is committed.
type Replicator interface {
	ReplicateSecret(cmd Command) (Result, error)
}

// Op names a secret store mutation.
type Op string

// The mutations: the two writes Store has.
const (
	OpPutIfAbsent Op = "put_if_absent"
	OpPut         Op = "put"
)

// Command is one replicated secret write. A generated value is chosen before
// the command is made, so every replica stores the same one.
type Command struct {
	Op     Op     `json:"op"`
	Path   string `json:"path"`
	Value  []byte `json:"value"`
	Origin Origin `json:"origin,omitempty"`
	Name   string `json:"name,omitempty"`
}

// Result is what applying a command returned.
type Result struct {
	Current    []byte `json:"current,omitempty"`
	HeldExists bool   `json:"held_exists,omitempty"`
	HeldOrigin Origin `json:"held_origin,omitempty"`
	ErrKind    string `json:"err_kind,omitempty"`
	Err        string `json:"err,omitempty"`
}

var secretSentinels = map[string]error{"holder_quota": ErrHolderQuota, "store_full": ErrStoreFull}

func secretResult(err error) Result {
	if err == nil {
		return Result{}
	}
	for k, s := range secretSentinels {
		if errors.Is(err, s) {
			return Result{ErrKind: k, Err: err.Error()}
		}
	}
	return Result{ErrKind: "other", Err: err.Error()}
}

func (r Result) err() error {
	if r.ErrKind == "" {
		return nil
	}
	return wireErr{r.Err, secretSentinels[r.ErrKind]}
}

// wireErr is an error that crossed the log: the text, and the sentinel.
type wireErr struct {
	msg string
	is  error
}

func (e wireErr) Error() string { return e.msg }
func (e wireErr) Unwrap() error { return e.is }

// Apply runs one replicated write against the local store. Replicas apply
// the same writes in the same order, so quotas and first-writer-wins decide
// the same way everywhere.
func (s *MemoryStore) Apply(cmd Command) Result {
	switch cmd.Op {
	case OpPutIfAbsent:
		cur, held, err := s.PutIfAbsent(context.Background(), cmd.Path, cmd.Value, Holder{origin: cmd.Origin, name: cmd.Name})
		r := secretResult(err)
		r.Current, r.HeldExists, r.HeldOrigin = cur, held.Exists, held.Origin
		return r
	case OpPut:
		held, err := s.Put(context.Background(), cmd.Path, cmd.Value)
		r := secretResult(err)
		r.HeldExists, r.HeldOrigin = held.Exists, held.Origin
		return r
	}
	return secretResult(fmt.Errorf("unknown secrets command %q", cmd.Op))
}

// ReplicatedStore is the Store of an HA replica: reads are local, writes go
// through the replicator and are applied to the local MemoryStore by Apply.
type ReplicatedStore struct {
	*MemoryStore
	Repl Replicator
}

// write checks the value, replicates cmd, and returns this replica's result.
func (s ReplicatedStore) write(cmd Command) (Result, error) {
	if err := s.checkValue(cmd.Value); err != nil {
		return Result{}, err
	}
	res, err := s.Repl.ReplicateSecret(cmd)
	if err != nil {
		return Result{}, err
	}
	return res, res.err()
}

// PutIfAbsent replicates a compare-and-set; the first committed write for a
// path wins at every replica.
func (s ReplicatedStore) PutIfAbsent(_ context.Context, path string, value []byte, by Holder) ([]byte, Held, error) {
	res, err := s.write(Command{Op: OpPutIfAbsent, Path: path, Value: value, Origin: by.origin, Name: by.name})
	if err != nil {
		return nil, Held{}, err
	}
	return res.Current, Held{Exists: res.HeldExists, Origin: res.HeldOrigin}, nil
}

// Put replicates an operator write.
func (s ReplicatedStore) Put(_ context.Context, path string, value []byte) (Held, error) {
	res, err := s.write(Command{Op: OpPut, Path: path, Value: value})
	if err != nil {
		return Held{}, err
	}
	return Held{Exists: res.HeldExists, Origin: res.HeldOrigin}, nil
}

// SnapshotEntry is one stored path in a snapshot.
type SnapshotEntry struct {
	Path   string `json:"path"`
	Value  []byte `json:"value"`
	Origin Origin `json:"origin"`
	Name   string `json:"name,omitempty"`
}

// Dump returns every stored path, for a joining or recovering replica.
func (s *MemoryStore) Dump() []SnapshotEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SnapshotEntry, 0, len(s.values))
	for p, e := range s.values {
		out = append(out, SnapshotEntry{Path: p, Value: append([]byte(nil), e.value...), Origin: e.holder.origin, Name: e.holder.name})
	}
	return out
}

// Restore replaces the store's contents with a snapshot.
func (s *MemoryStore) Restore(entries []SnapshotEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = make(map[string]entry, len(entries))
	s.holders = make(map[Holder]int)
	s.bytes = 0
	for _, e := range entries {
		s.storeLocked(e.Path, e.Value, Holder{origin: e.Origin, name: e.Name})
	}
}

// entryBytes bounds the JSON size of one SnapshotEntry: the value in base64,
// path and name escaped (at most twice their length for the characters a
// path may hold), and the field names.
func entryBytes(path string, value []byte, by Holder) int64 {
	return int64(64 + 2*(len(path)+len(by.name)+len(by.origin)) + 4*((len(value)+2)/3))
}

// SnapshotBytes bounds the size the store adds to a CDS HA snapshot header,
// in O(1).
func (s *MemoryStore) SnapshotBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bytes
}

// SnapshotGrowth is how many bytes applying cmd now would add to
// SnapshotBytes; 0 for a write that would not grow it (a put_if_absent on a
// held path, an overwrite with a value no larger).
func (s *MemoryStore) SnapshotGrowth(cmd Command) int64 {
	by := Holder{origin: cmd.Origin, name: cmd.Name}
	if cmd.Op == OpPut {
		by = OperatorHolder()
	}
	s.mu.RLock()
	prior, held := s.values[cmd.Path]
	s.mu.RUnlock()
	add := entryBytes(cmd.Path, cmd.Value, by)
	switch {
	case !held:
		return add
	case cmd.Op == OpPutIfAbsent:
		return 0
	}
	return max(0, add-entryBytes(cmd.Path, prior.value, prior.holder))
}
