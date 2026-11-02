package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/worker"

// workerCmd is the worker group: worker_operator.go and worker_node.go add
// each build's commands.
var workerCmd = worker.NewCmd()

func init() {
	rootCmd.AddCommand(workerCmd)
}
