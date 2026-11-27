package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/collateral"

func init() {
	rootCmd.AddCommand(collateral.NewCmd())
}
