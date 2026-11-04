//go:build !c8s_node && linux

package main

import (
	"slices"
	"testing"
)

// The images bake this build, so it stages a worker document too.
func TestOperatorBuildOffersEveryWorkerCommand(t *testing.T) {
	if got := workerSubcommands(t); !slices.Equal(got, []string{"new", "stage"}) {
		t.Fatalf("worker commands = %v, want new and stage", got)
	}
}
