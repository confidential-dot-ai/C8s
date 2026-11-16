package main

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

// workerSubcommands are the names of the worker group's commands, sorted.
func workerSubcommands(t *testing.T) []string {
	t.Helper()
	i := slices.IndexFunc(rootCmd.Commands(), func(c *cobra.Command) bool { return c.Name() == "worker" })
	if i < 0 {
		t.Fatal("no worker command")
	}
	var names []string
	for _, child := range rootCmd.Commands()[i].Commands() {
		names = append(names, child.Name())
	}
	slices.Sort(names)
	return names
}
