package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/attestproxy"

func init() {
	rootCmd.AddCommand(attestproxy.NewCmd())
}
