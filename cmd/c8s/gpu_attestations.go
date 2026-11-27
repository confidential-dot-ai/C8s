package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/gpuattestations"

func init() {
	rootCmd.AddCommand(gpuattestations.NewCmd())
}
