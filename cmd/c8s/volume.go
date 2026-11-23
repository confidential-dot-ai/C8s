package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/volume"

func init() {
	rootCmd.AddCommand(volume.NewCmd())
}
