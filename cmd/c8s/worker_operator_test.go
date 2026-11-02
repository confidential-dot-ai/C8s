//go:build !c8s_node

package main

import (
	"slices"
	"testing"
)

// Only a worker image stages a worker document.
func TestOperatorBuildOffersNoWorkerStage(t *testing.T) {
	if got := workerSubcommands(t); !slices.Equal(got, []string{"new"}) {
		t.Fatalf("worker commands = %v, want new", got)
	}
}
