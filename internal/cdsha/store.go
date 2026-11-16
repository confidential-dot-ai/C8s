package cdsha

import (
	"context"
	"errors"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// Store is the four calls the chain needs from an untrusted store with a
// linearizable read and a conditional write on one key. The head is opaque
// bytes: CASHead compares exactly the bytes GetHead returned.
type Store interface {
	// GetHead returns the head, nil when there is none.
	GetHead(ctx context.Context) ([]byte, error)
	// CASHead sets the head to next if it is old (nil: absent), else ErrConflict.
	CASHead(ctx context.Context, old, next []byte) error
	// PutEntry stores data under hash; it is idempotent.
	PutEntry(ctx context.Context, hash cdschain.Hash, data []byte) error
	// GetEntry returns the data under hash, nil when there is none.
	GetEntry(ctx context.Context, hash cdschain.Hash) ([]byte, error)
}

// ErrConflict is a CASHead whose old head is not the store's.
var ErrConflict = errors.New("the store head is not the expected head")

// MaxStoreAnswer caps one store answer: one entry is the largest.
const MaxStoreAnswer = 4 << 20
