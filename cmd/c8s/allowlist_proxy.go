package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/allowlistproxy"

func init() {
	rootCmd.AddCommand(allowlistproxy.NewCmd())
}
