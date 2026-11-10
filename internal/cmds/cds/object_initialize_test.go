package cds

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

type initializationTestStore struct {
	objectstate.Store
	loads   atomic.Int64
	creates atomic.Int64
	load    func(context.Context) (objectstate.Object, error)
	create  func(
		context.Context,
		[]byte,
	) (string, error)
}

func (s *initializationTestStore) Load(ctx context.Context) (objectstate.Object, error) {
	s.loads.Add(1)
	if s.load != nil {
		return s.load(ctx)
	}
	return s.Store.Load(ctx)
}

func (s *initializationTestStore) Create(
	ctx context.Context,
	data []byte,
) (string, error) {
	s.creates.Add(1)
	if s.create != nil {
		return s.create(
			ctx,
			data,
		)
	}
	return s.Store.Create(
		ctx,
		data,
	)
}

func assertInitializedCurrentState(
	t *testing.T,
	h *objectAcceptance,
	store objectstate.Store,
	view *objectView,
) {
	t.Helper()
	object, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := h.cipher.Open(object.Data)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	committed, err := readObjectView(
		h.cfg,
		plain,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer committed.Stop()
	if !reflect.DeepEqual(
		view.state,
		committed.state,
	) || !bytes.Equal(
		view.ca.CA.Cert.Raw,
		committed.ca.CA.Cert.Raw,
	) {
		t.Fatal("initialization returned state other than the committed current object")
	}
}

func TestInitializeObjectStateExistingIsIdempotent(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	store := &initializationTestStore{Store: h.store}
	for range 2 {
		view, err := initializeObjectState(
			t.Context(),
			h.cfg,
			store,
			h.cipher,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer view.Stop()
		assertInitializedCurrentState(
			t,
			h,
			h.store,
			view,
		)
	}
	if store.creates.Load() != 0 || store.loads.Load() != 2 {
		t.Fatal("existing state was not recovered with one read and no creation per call")
	}
}

func TestInitializeObjectStateConfirmsCreationAndLostAcknowledgment(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	for _, lostAck := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "acknowledged", true: "lost acknowledgment"}[lostAck],
			func(t *testing.T) {
				base := &acceptanceObjectStore{}
				store := &initializationTestStore{Store: base}
				store.create = func(
					ctx context.Context,
					data []byte,
				) (string, error) {
					etag, err := base.Create(
						ctx,
						data,
					)
					if err == nil && lostAck {
						err = objectstate.ErrUnknown
					}
					return etag, err
				}
				view, err := initializeObjectState(
					t.Context(),
					h.cfg,
					store,
					h.cipher,
				)
				if err != nil {
					t.Fatal(err)
				}
				defer view.Stop()
				assertInitializedCurrentState(
					t,
					h,
					base,
					view,
				)
				if view.state.Revision != 1 || store.creates.Load() != 1 || store.loads.Load() != 2 {
					t.Fatal("initialization did not create exactly once and confirm the current state")
				}
			},
		)
	}
}

func TestInitializeObjectStateUnknownMissingDoesNotRecreate(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	base := &acceptanceObjectStore{}
	store := &initializationTestStore{Store: base}
	var pending []byte
	store.create = func(
		_ context.Context,
		data []byte,
	) (string, error) {
		pending = bytes.Clone(data)
		return "", objectstate.ErrUnknown
	}
	view, err := initializeObjectState(
		t.Context(),
		h.cfg,
		store,
		h.cipher,
	)
	if view != nil {
		view.Stop()
		t.Fatal("unconfirmed initialization returned a CA")
	}
	if !errors.Is(
		err,
		objectstate.ErrUnknown,
	) || !errors.Is(
		err,
		objectstate.ErrNotFound,
	) || store.creates.Load() != 1 || store.loads.Load() != 2 {
		t.Fatal("missing confirmation did not preserve the unknown outcome without retrying")
	}
	// A timed-out conditional write can still commit after the missing read.
	if _, err := base.Create(
		t.Context(),
		pending,
	); err != nil {
		t.Fatal(err)
	}
	view, err = initializeObjectState(
		t.Context(),
		h.cfg,
		store,
		h.cipher,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Stop()
	assertInitializedCurrentState(
		t,
		h,
		base,
		view,
	)
	if store.creates.Load() != 1 {
		t.Fatal("recovering the late commitment attempted another creation")
	}
}

func TestInitializeObjectStateFailedConfirmationReturnsNoCA(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	unavailable := errors.New("confirmation read unavailable")
	for _, createErr := range []error{nil, objectstate.ErrUnknown} {
		for _, confirmation := range []string{"missing", "unavailable", "corrupt"} {
			name := "acknowledged/" + confirmation
			if createErr != nil {
				name = "unknown/" + confirmation
			}
			t.Run(
				name,
				func(t *testing.T) {
					base := &acceptanceObjectStore{}
					store := &initializationTestStore{Store: base}
					store.create = func(
						ctx context.Context,
						data []byte,
					) (string, error) {
						etag, err := base.Create(
							ctx,
							data,
						)
						if err != nil {
							return "", err
						}
						return etag, createErr
					}
					store.load = func(ctx context.Context) (objectstate.Object, error) {
						if store.loads.Load() == 1 {
							return base.Load(ctx)
						}
						switch confirmation {
						case "missing":
							return objectstate.Object{}, objectstate.ErrNotFound
						case "unavailable":
							return objectstate.Object{}, unavailable
						default:
							return objectstate.Object{Data: []byte("corrupt current object")}, nil
						}
					}
					view, err := initializeObjectState(
						t.Context(),
						h.cfg,
						store,
						h.cipher,
					)
					if view != nil {
						view.Stop()
						t.Fatal("failed confirmation disclosed the candidate CA")
					}
					if err == nil || store.creates.Load() != 1 || store.loads.Load() != 2 {
						t.Fatal("failed confirmation did not stop after one creation attempt")
					}
					if !errors.Is(
						err,
						objectstate.ErrUnknown,
					) {
						t.Fatal("failed confirmation did not report an unknown initialization outcome")
					}
					if confirmation == "unavailable" && !errors.Is(
						err,
						unavailable,
					) {
						t.Fatal("confirmation lost its underlying read error")
					}
				},
			)
		}
	}
}

func TestInitializeObjectStateConcurrentInitializersReturnWinner(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	base := &acceptanceObjectStore{}
	store := &initializationTestStore{Store: base}
	var arrivals, conflicts atomic.Int64
	ready := make(chan struct{})
	store.load = func(ctx context.Context) (objectstate.Object, error) {
		object, err := base.Load(ctx)
		if errors.Is(
			err,
			objectstate.ErrNotFound,
		) {
			if arrivals.Add(1) == 2 {
				close(ready)
			}
			select {
			case <-ready:
			case <-ctx.Done():
				return objectstate.Object{}, ctx.Err()
			}
		}
		return object, err
	}
	store.create = func(
		ctx context.Context,
		data []byte,
	) (string, error) {
		etag, err := base.Create(
			ctx,
			data,
		)
		if errors.Is(
			err,
			objectstate.ErrConflict,
		) {
			conflicts.Add(1)
		}
		return etag, err
	}
	type result struct {
		view *objectView
		err  error
	}
	results := make(
		chan result,
		2,
	)
	ctx, cancel := context.WithTimeout(
		t.Context(),
		5*time.Second,
	)
	defer cancel()
	for range 2 {
		go func() {
			view, err := initializeObjectState(
				ctx,
				h.cfg,
				store,
				h.cipher,
			)
			results <- result{
				view: view,
				err:  err,
			}
		}()
	}
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Error(got.err)
			continue
		}
		defer got.view.Stop()
		assertInitializedCurrentState(
			t,
			h,
			base,
			got.view,
		)
	}
	if store.creates.Load() != 2 || conflicts.Load() != 1 || store.loads.Load() != 4 {
		t.Fatal("concurrent initializers did not each confirm the single committed winner")
	}
}

func TestInitializeObjectStateRejectsUnreadableExistingState(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	object, err := h.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(object.Data)
	corrupt[len(corrupt)-1] ^= 1
	wrongKey, err := objectCipher(
		h.cfg,
		bytes.Repeat(
			[]byte{0x52},
			32,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	invalidState, err := h.cipher.Seal([]byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	wrongLaunch := h.cfg
	wrongLaunch.measuredFile = append(
		bytes.Clone(h.cfg.measuredFile),
		'\n',
	)
	for _, name := range []string{"read failure", "corrupt", "wrong key", "wrong launch", "invalid state"} {
		t.Run(
			name,
			func(t *testing.T) {
				base := &acceptanceObjectStore{
					data:    bytes.Clone(object.Data),
					version: 1,
				}
				store := &initializationTestStore{Store: base}
				cfg, cipher := h.cfg, h.cipher
				switch name {
				case "read failure":
					store.load = func(context.Context) (objectstate.Object, error) {
						return objectstate.Object{}, errors.New("initial read unavailable")
					}
				case "corrupt":
					base.data = corrupt
				case "wrong key":
					cipher = wrongKey
				case "wrong launch":
					cfg = wrongLaunch
				case "invalid state":
					base.data = invalidState
				}
				view, err := initializeObjectState(
					t.Context(),
					cfg,
					store,
					cipher,
				)
				if view != nil {
					view.Stop()
					t.Fatal("unreadable initial object returned a CA")
				}
				if err == nil || store.creates.Load() != 0 || store.loads.Load() != 1 {
					t.Fatal("unreadable initial object was treated as initialization permission")
				}
			},
		)
	}
}

func TestInitializeObjectStateBoundsStoreCalls(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	base := &acceptanceObjectStore{}
	store := &initializationTestStore{Store: base}
	checkDeadline := func(ctx context.Context) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Error("initialization store call has no ten-second deadline")
		}
	}
	store.load = func(ctx context.Context) (objectstate.Object, error) {
		checkDeadline(ctx)
		return base.Load(ctx)
	}
	store.create = func(
		ctx context.Context,
		data []byte,
	) (string, error) {
		checkDeadline(ctx)
		return base.Create(
			ctx,
			data,
		)
	}
	view, err := initializeObjectState(
		t.Context(),
		h.cfg,
		store,
		h.cipher,
	)
	if err != nil {
		t.Fatal(err)
	}
	view.Stop()
	store = &initializationTestStore{Store: &acceptanceObjectStore{}}
	store.load = func(ctx context.Context) (objectstate.Object, error) {
		<-ctx.Done()
		return objectstate.Object{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(
		t.Context(),
		10*time.Millisecond,
	)
	defer cancel()
	view, err = initializeObjectState(
		ctx,
		h.cfg,
		store,
		h.cipher,
	)
	if view != nil {
		view.Stop()
		t.Fatal("canceled initialization returned a CA")
	}
	if !errors.Is(
		err,
		context.DeadlineExceeded,
	) || store.creates.Load() != 0 {
		t.Fatal("initialization ignored the caller deadline")
	}
}
