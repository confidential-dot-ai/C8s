package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/secrets"

func init() {
	rootCmd.AddCommand(secrets.NewCmd())
}
