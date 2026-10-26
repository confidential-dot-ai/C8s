package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/nodecredential"

func init() {
	rootCmd.AddCommand(nodecredential.NewCmd())
}
