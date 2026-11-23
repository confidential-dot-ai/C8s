package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/getcert"

func init() {
	rootCmd.AddCommand(getcert.NewCmd())
}
