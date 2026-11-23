package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/acme"

func init() {
	rootCmd.AddCommand(acme.NewCmd())
}
