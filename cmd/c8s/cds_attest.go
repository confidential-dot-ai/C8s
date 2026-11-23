package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cdsattest"

func init() {
	rootCmd.AddCommand(cdsattest.NewCmd())
}
