//go:build !c8s_node

package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/worker"

func init() {
	workerCmd.AddCommand(worker.NewNewCmd(), worker.NewFloorCmd(), newWorkerControlPlaneCmd())
}
