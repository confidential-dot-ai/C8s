//go:build linux

package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/armtlsmesh"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"armtls-mesh [flags]",
		"Run the C8s mesh endpoint of one pod",
		armtlsmesh.Run,
	))
}
