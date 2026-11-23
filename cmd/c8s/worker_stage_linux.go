package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/worker"

// In every Linux build, as the worker image bakes the untagged binary.
func init() {
	workerCmd.AddCommand(worker.NewStageCmd())
}
