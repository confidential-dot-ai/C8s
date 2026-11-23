//go:build linux

package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/volumed"

func init() {
	rootCmd.AddCommand(volumed.NewCmd())
}
