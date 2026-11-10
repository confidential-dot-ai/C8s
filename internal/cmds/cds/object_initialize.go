package cds

import (
	"context"
	"errors"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

const objectInitializationStoreTimeout = 10 * time.Second

// The SNP custodian must first authenticate the independent owner's explicit
// new-cluster authorization. Ordinary recovery must never call this function.
// Deleting current state, including lifecycle expiry, invalidates the assumption
// that an initialized cluster can never appear uninitialized again.
func initializeObjectState(
	ctx context.Context,
	cfg config,
	store objectstate.Store,
	cipher *objectstate.Cipher,
) (*objectView, error) {
	ctx, cancel := context.WithTimeout(
		ctx,
		objectRequestTimeout,
	)
	defer cancel()
	current, err := loadInitializedObjectView(
		ctx,
		cfg,
		store,
		cipher,
	)
	if !errors.Is(
		err,
		objectstate.ErrNotFound,
	) {
		return current, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	candidate, err := initialObjectView(cfg)
	if err != nil {
		return nil, err
	}
	defer candidate.Stop()
	plain, err := candidate.encode()
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	sealed, err := cipher.Seal(plain)
	if err != nil {
		return nil, err
	}
	writeCtx, cancelWrite := context.WithTimeout(
		ctx,
		objectInitializationStoreTimeout,
	)
	_, createErr := store.Create(
		writeCtx,
		sealed,
	)
	cancelWrite()
	// Only a fresh authenticated read can identify the committed winner. A
	// missing read cannot rule out a timed-out Create committing later.
	current, err = loadInitializedObjectView(
		ctx,
		cfg,
		store,
		cipher,
	)
	if err != nil {
		return nil, errors.Join(
			objectstate.ErrUnknown,
			createErr,
			err,
		)
	}
	return current, nil
}

func loadInitializedObjectView(
	ctx context.Context,
	cfg config,
	store objectstate.Store,
	cipher *objectstate.Cipher,
) (*objectView, error) {
	ctx, cancel := context.WithTimeout(
		ctx,
		objectInitializationStoreTimeout,
	)
	defer cancel()
	object, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	plain, err := cipher.Open(object.Data)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	view, err := readObjectView(
		cfg,
		plain,
	)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		view.Stop()
		return nil, err
	}
	return view, nil
}
