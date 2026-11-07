package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/cds"

func init() {
	rootCmd.AddCommand(cds.NewCmd())
}
