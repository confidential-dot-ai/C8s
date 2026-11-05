package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"

func init() {
	rootCmd.AddCommand(podstatus.NewCmd(), podstatus.NewAttestCmd())
}
