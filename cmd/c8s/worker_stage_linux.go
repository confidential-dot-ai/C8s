package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/worker"

// In every Linux build, as the worker image bakes the untagged binary.
func init() {
	workerCmd.AddCommand(worker.NewStageCmd())
}
