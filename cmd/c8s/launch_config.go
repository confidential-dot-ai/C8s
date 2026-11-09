package main

import "github.com/confidential-dot-ai/c8s/internal/podlaunch"

func init() {
	rootCmd.AddCommand(podlaunch.NewCmd())
}
