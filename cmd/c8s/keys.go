package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/keys"

func init() {
	rootCmd.AddCommand(keys.NewCmd())
}
