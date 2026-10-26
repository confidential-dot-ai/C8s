package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/join"

func init() {
	rootCmd.AddCommand(join.NewJoinCmd(), join.NewReleaseCmd())
}
