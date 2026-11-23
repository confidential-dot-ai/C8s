package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/probefile"

func init() {
	rootCmd.AddCommand(probefile.NewCmd())
}
