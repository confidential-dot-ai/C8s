package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/ta"

func init() {
	rootCmd.AddCommand(ta.NewCmd())
}
