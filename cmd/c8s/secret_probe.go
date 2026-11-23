package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/secretprobe"

func init() {
	rootCmd.AddCommand(secretprobe.NewCmd())
}
