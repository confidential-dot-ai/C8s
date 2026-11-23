package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/measurements"

func init() {
	rootCmd.AddCommand(measurements.NewCmd())
}
