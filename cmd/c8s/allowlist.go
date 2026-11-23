package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/allowlist"

func init() {
	rootCmd.AddCommand(allowlist.NewCmd())
}
