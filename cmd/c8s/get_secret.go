package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/getsecret"

func init() {
	rootCmd.AddCommand(getsecret.NewCmd())
}
