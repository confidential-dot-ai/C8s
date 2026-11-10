// Package objectstate stores the encrypted current state of one CDS cluster.
package objectstate

import (
	"context"
	"errors"
)

var (
	ErrNotFound = errors.New("object state is missing")
	ErrConflict = errors.New("object state changed")
	ErrUnknown  = errors.New("object state write outcome is unknown")
	ErrTooLarge = errors.New("object state exceeds its size limit")
)

type Object struct {
	Data []byte
	ETag string
}

// Store must provide linearizable reads and conditional writes on one object.
// ErrConflict proves this attempt did not commit; ErrUnknown does not. A caller
// must never reapply an operation after ErrUnknown without resolving its outcome.
type Store interface {
	Load(context.Context) (Object, error)
	// Create is for explicit provisioning, never recovery from a missing object.
	Create(
		context.Context,
		[]byte,
	) (string, error)
	CompareAndSwap(
		context.Context,
		string,
		[]byte,
	) (string, error)
}
