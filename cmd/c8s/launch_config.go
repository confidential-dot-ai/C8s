package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/podlaunch"

func init() {
	rootCmd.AddCommand(podlaunch.NewCmd())
}
