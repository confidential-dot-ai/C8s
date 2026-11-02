//go:build !c8s_node

package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/worker"

func init() {
	rootCmd.AddCommand(worker.NewCmd())
}
