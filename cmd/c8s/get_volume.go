//go:build linux

package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/getvolume"

func init() {
	rootCmd.AddCommand(getvolume.NewCmd())
}
