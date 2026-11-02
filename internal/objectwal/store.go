// Package objectwal implements the experimental CDS log over a strongly
// consistent object store. Publishing the encrypted head with a conditional
// PUT commits a record; uploading an immutable record alone commits nothing.
package objectwal

import (
	"context"
	"errors"
)

var (
	ErrNotFound = errors.New("object WAL: object not found")
	ErrConflict = errors.New("object WAL: conditional write conflicted")
	ErrInDoubt  = errors.New("object WAL: commit outcome unknown; do not replay the operation blindly")
	ErrCorrupt  = errors.New("object WAL: invalid or rolled-back history")
)

const MaxObjectBytes = 64 << 20

type Object struct {
	Data []byte
	ETag string
}

// Store must provide linearizable GET and conditional PUT on a key. An empty
// expected ETag means create-if-absent. Implementations must never transparently
// retry a conditional PUT: a lost response followed by 412 is an unknown outcome.
// There is deliberately no Delete or List: this pilot retains the whole history.
type Store interface {
	Get(context.Context, string) (Object, error)
	Put(context.Context, string, []byte, string) (string, error)
}

// Machine is local, disposable state. Log serializes Apply, Capture and Restore.
// Apply must be deterministic, including its response. A failed Apply stops the
// log permanently; the caller must stop serving and reconstruct a new machine.
type Machine interface {
	Apply(uint64, []byte) (any, error)
	Capture() ([]byte, error)
	Restore([]byte) (uint64, error)
}
