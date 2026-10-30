//go:build !c8s_dev

package cds

import (
	"context"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// A release serves its cluster as the singleton: a configuration asking for a
// replica set is refused, not served with its ha block ignored.
func TestAReleaseServesNoReplicaSet(t *testing.T) {
	cfg, state := replicatedRunConfig(t, mockapi.New(t).URL())

	_, err := newBackend(context.Background(), cfg, state)
	if !errors.Is(err, errNoReplicaSet) {
		t.Fatalf("newBackend = %v, want errNoReplicaSet", err)
	}
}
