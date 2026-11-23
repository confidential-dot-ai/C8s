//go:build linux

// Command armtls-mesh is a thin wrapper around the `c8s armtls-mesh` cobra
// subcommand.
package main

import (
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/armtlsmesh"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
)

func main() { cmdsutil.RunMain(armtlsmesh.Run) }
