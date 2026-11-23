package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/taattest"

func init() {
	rootCmd.AddCommand(taattest.NewCmd())
}
