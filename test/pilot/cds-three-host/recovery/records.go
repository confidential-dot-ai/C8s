// Package recovery stores the disposable fixture's encrypted recovery capsule
// and encrypted test-client witness in its existing HA metadata namespace.
// It introduces no key-release policy: CurrentAuthority still validates every
// release against CDS's current signed image policy.
package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

type Kind string

const (
	Registration Kind = "registration"
	Witness      Kind = "witness"
	MaxBytes          = 32 << 10
	firstVersion      = "0000000000000001"
)

type Metadata interface {
	Read(context.Context, []string) ([]metadatapilot.Record, error)
	Commit(context.Context, metadatapilot.Transaction) error
}

func key(kind Kind) (string, error) {
	if kind != Registration && kind != Witness {
		return "", errors.New("unknown protected fixture record")
	}
	h := sha256.Sum256([]byte("c8s/cds-three-host/protected-fixture/v1\x00" + string(kind)))
	return hex.EncodeToString(h[:]), nil
}

// Publish is one conditional transaction and never retries an uncertain write.
// A published registration cannot be overwritten by a fresh guest attempting
// to enroll a different key under an already-used namespace.
func Publish(ctx context.Context, m Metadata, kind Kind, ciphertext []byte) error {
	k, err := key(kind)
	if err != nil {
		return err
	}
	if m == nil || len(ciphertext) == 0 || len(ciphertext) > MaxBytes {
		return errors.New("bounded protected record and metadata required")
	}
	return m.Commit(ctx, metadatapilot.Transaction{
		Checks: []metadatapilot.Check{{Key: k}},
		Writes: []metadatapilot.Record{{Key: k, Version: firstVersion, Value: bytes.Clone(ciphertext)}},
	})
}

func Read(ctx context.Context, m Metadata, kind Kind) ([]byte, error) {
	k, err := key(kind)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("metadata required")
	}
	rows, err := m.Read(ctx, []string{k})
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || rows[0].Key != k {
		return nil, objectwal.ErrCorrupt
	}
	if rows[0].Version == "" && len(rows[0].Value) == 0 {
		return nil, objectwal.ErrNotFound
	}
	if rows[0].Version != firstVersion || len(rows[0].Value) == 0 || len(rows[0].Value) > MaxBytes {
		return nil, objectwal.ErrCorrupt
	}
	return bytes.Clone(rows[0].Value), nil
}
