package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/routes"

func init() {
	rootCmd.AddCommand(routes.NewCmd())
}
