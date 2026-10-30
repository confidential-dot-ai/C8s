package main

import (
	"slices"
	"testing"
)

func TestNodeServicesOnlyExposesBootstrapCommands(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"node-services"})
	if err != nil || cmd == rootCmd {
		t.Fatalf("node-services command: %v", err)
	}
	children := cmd.Commands()
	var names []string
	for _, child := range children {
		names = append(names, child.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"cilium-node-ip", "node-ip", "prepare"}) {
		t.Fatalf("unexpected node-service dispatch: %v", names)
	}
	for _, child := range children {
		if err := child.ValidateArgs([]string{"unmeasured-override"}); err == nil {
			t.Fatalf("%s accepts an extra argument", child.Name())
		}
	}
}
