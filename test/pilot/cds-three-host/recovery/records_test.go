package recovery

import (
	"context"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

type records struct {
	row    metadatapilot.Record
	calls  int
	result error
}

func (r *records) Read(_ context.Context, keys []string) ([]metadatapilot.Record, error) {
	if r.result != nil {
		return nil, r.result
	}
	row := r.row
	row.Key = keys[0]
	return []metadatapilot.Record{row}, nil
}
func (r *records) Commit(_ context.Context, txn metadatapilot.Transaction) error {
	r.calls++
	if r.result != nil {
		return r.result
	}
	if len(txn.Checks) != 1 || txn.Checks[0].Version != "" || len(txn.Writes) != 1 || txn.Checks[0].Key != txn.Writes[0].Key {
		panic("registration requires one create-if-absent transaction")
	}
	if r.row.Version != "" {
		return objectwal.ErrConflict
	}
	r.row = txn.Writes[0]
	return nil
}

func TestRegistrationCannotBeReenrolledOrRewritten(t *testing.T) {
	ctx, store := t.Context(), &records{}
	if _, err := Read(ctx, store, Registration); !errors.Is(err, objectwal.ErrNotFound) {
		t.Fatal(err)
	}
	data := []byte("encrypted original capsule")
	if err := Publish(ctx, store, Registration, data); err != nil {
		t.Fatal(err)
	}
	clear(data)
	if err := Publish(ctx, store, Registration, []byte("other capsule")); !errors.Is(err, objectwal.ErrConflict) {
		t.Fatal("existing registration replaced", err)
	}
	read, err := Read(ctx, store, Registration)
	if err != nil || string(read) != "encrypted original capsule" {
		t.Fatal("original capsule changed", err)
	}
	clear(read)
	store.row.Version = "0000000000000002"
	if _, err = Read(ctx, store, Registration); !errors.Is(err, objectwal.ErrCorrupt) {
		t.Fatal("rewritten registration accepted", err)
	}
}

func TestUnknownCommitIsNotRetriedAndUnavailableReadFails(t *testing.T) {
	store := &records{result: objectwal.ErrInDoubt}
	if err := Publish(t.Context(), store, Registration, []byte("sealed")); !errors.Is(err, objectwal.ErrInDoubt) || store.calls != 1 {
		t.Fatal("uncertain publication retried", store.calls, err)
	}
	if _, err := Read(t.Context(), store, Registration); !errors.Is(err, objectwal.ErrInDoubt) {
		t.Fatal("unavailable metadata was treated as absent", err)
	}
	if err := Publish(t.Context(), store, Witness, make([]byte, MaxBytes+1)); err == nil || store.calls != 1 {
		t.Fatal("oversized record dispatched")
	}
}
