// Command c8s-runc is the measured OCI runtime wrapper the node image
// installs as the runc handler's containerd BinaryName. It denies runc `exec`
// in a locked build and hands every other verb to the real runtime.
//
// The node image ships it as an argv alias of the c8s binary (see
// cmd/c8s/main.go); this command exists so a debug wrapper can be built
// separately:
//
//	go build -ldflags '-X github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/c8srunc.mode=debug' ./cmd/c8s-runc
package main

import (
	"os"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/c8srunc"
)

func main() { os.Exit(c8srunc.Main(os.Args)) }
