package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/routes"

func init() {
	rootCmd.AddCommand(routes.NewCmd())
}
