//go:build c8s_node

package main

import (
	"slices"
	"testing"
)

// A worker drafts and admits no documents.
func TestNodeBuildOffersOnlyWorkerStage(t *testing.T) {
	if got := workerSubcommands(t); !slices.Equal(got, []string{"stage"}) {
		t.Fatalf("worker commands = %v, want only stage", got)
	}
}
