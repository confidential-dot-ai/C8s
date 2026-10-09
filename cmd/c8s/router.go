package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/router"

func init() {
	rootCmd.AddCommand(router.NewCmd())
}
