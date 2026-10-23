package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/secretprobe"

func init() {
	rootCmd.AddCommand(secretprobe.NewCmd())
}
