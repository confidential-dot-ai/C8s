//go:build !c8s_node

package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cds"

func init() {
	rootCmd.AddCommand(cds.NewCmd())
}
