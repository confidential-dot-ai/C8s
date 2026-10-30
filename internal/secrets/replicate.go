package secrets

import (
	"context"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/replicate"
)

// Committer takes one secret write: a single CDS applies it, a CDS HA replica
// commits it to the cluster's log first.
type Committer = replicate.Committer[Command, Result]

// Handle is the secret store as its writers hold it. It is the only way to
// write, so no write path asks which kind of CDS it serves.
type Handle struct {
	store  *MemoryStore
	commit Committer
}

var _ Store = (*Handle)(nil)

// Local is a handle whose writes apply to the store's own entries.
func (s *MemoryStore) Local() *Handle {
	return &Handle{
		store:  s,
		commit: replicate.Local[Command, Result](s),
	}
}

// CommittedBy is a handle whose writes c commits to a CDS HA cluster before
// any replica applies them.
func (s *MemoryStore) CommittedBy(c Committer) *Handle {
	return &Handle{
		store:  s,
		commit: c,
	}
}

func (h *Handle) Get(ctx context.Context, path string) ([]byte, error) {
	return h.store.Get(ctx, path)
}

func (h *Handle) TopHolders(n int) []HolderPaths {
	return h.store.TopHolders(n)
}

func (h *Handle) Len() int {
	return h.store.Len()
}

type Op string

const (
	OpPutIfAbsent Op = "put_if_absent"
	OpPut         Op = "put"
)

// Command is one write. The value a workload's path is seeded with is chosen
// before the command is made, so every replica stores the same one. Value is
// the plaintext: the log and its snapshots live in TEE memory.
type Command struct {
	Op    Op     `json:"op"`
	Path  string `json:"path"`
	Value []byte `json:"value"`
	// Origin and Name are the holder the path is charged to (OpPutIfAbsent).
	Origin Origin `json:"origin,omitempty"`
	Name   string `json:"name,omitempty"`
}

type Result struct {
	Current    []byte `json:"current,omitempty"`
	HeldExists bool   `json:"held_exists,omitempty"`
	HeldOrigin Origin `json:"held_origin,omitempty"`
	httputil.Status
}

// refusal is the error every replica reached alike applying the command.
func (r Result) refusal() error {
	return r.Err(sentinels)
}

// sentinels carries a refusal across the cluster's log, so a caller matches
// the same error at every replica as in a single CDS.
var sentinels = map[string]error{
	"holder_quota": ErrHolderQuota,
	"store_full":   ErrStoreFull,
}

// Apply runs one command against the entries this process holds. Replicas
// apply the same commands in the same order, so a quota and a first writer
// are decided the same way everywhere.
func (s *MemoryStore) Apply(cmd Command) Result {
	r, err := s.apply(cmd)
	r.Status = httputil.StatusOf(err, sentinels)
	return r
}

func (s *MemoryStore) apply(cmd Command) (Result, error) {
	if cmd.Path == "" {
		return Result{}, fmt.Errorf("secrets command %q carries no path", cmd.Op)
	}
	switch cmd.Op {
	case OpPutIfAbsent:
		by := Holder{
			origin: cmd.Origin,
			name:   cmd.Name,
		}
		current, held, err := s.putIfAbsent(cmd.Path, cmd.Value, by)
		return Result{
			Current:    current,
			HeldExists: held.Exists,
			HeldOrigin: held.Origin,
		}, err
	case OpPut:
		held, err := s.put(cmd.Path, cmd.Value)
		return Result{
			HeldExists: held.Exists,
			HeldOrigin: held.Origin,
		}, err
	}
	return Result{}, fmt.Errorf("unknown secrets command %q", cmd.Op)
}

// write refuses an oversized value before the command travels: an error is a
// store that could not take the write, a refusal in the result is what every
// replica made of it.
func (h *Handle) write(cmd Command) (Result, error) {
	if err := h.store.checkValue(cmd.Value); err != nil {
		return Result{}, err
	}
	res, err := h.commit.Commit(cmd)
	if err != nil {
		return Result{}, err
	}
	return res, res.refusal()
}

// PutIfAbsent stores value at path if nothing is there (see MemoryStore).
// Replicated, the first committed write for a path wins at every replica.
func (h *Handle) PutIfAbsent(_ context.Context, path string, value []byte, by Holder) ([]byte, Held, error) {
	res, err := h.write(Command{
		Op:     OpPutIfAbsent,
		Path:   path,
		Value:  value,
		Origin: by.origin,
		Name:   by.name,
	})
	if err != nil {
		return nil, Held{}, err
	}
	return res.Current, Held{
		Exists: res.HeldExists,
		Origin: res.HeldOrigin,
	}, nil
}

// Put stores value at path, replacing anything already there (see
// MemoryStore).
func (h *Handle) Put(_ context.Context, path string, value []byte) (Held, error) {
	res, err := h.write(Command{
		Op:    OpPut,
		Path:  path,
		Value: value,
	})
	if err != nil {
		return Held{}, err
	}
	return Held{
		Exists: res.HeldExists,
		Origin: res.HeldOrigin,
	}, nil
}
